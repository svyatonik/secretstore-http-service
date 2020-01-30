// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Parity Secret Store.

// Parity Secret Store is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Secret Store is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Secret Store.  If not, see <http://www.gnu.org/licenses/>.

use std::{future::Future, sync::Arc};
use futures::future::{TryFutureExt, ready};
use hyper::{
	Body, Method, Request, Response, Server, StatusCode, Uri,
	header::{self, HeaderValue},
	service::{make_service_fn, service_fn},
};
use jsonrpc_server_utils::cors::{self, AllowCors, AccessControlAllowOrigin};
use log::error;
use serde::Serialize;
use parity_secretstore_primitives::{
	Public, ecies_encrypt,
	error::Error as SecretStoreError,
	key_server::{DocumentKeyShadowRetrievalArtifacts, KeyServer},
	serialization::{SerializableBytes, SerializablePublic, SerializableEncryptedDocumentKeyShadow},
	service::ServiceTask,
};

mod parse;

type CorsDomains = Option<Vec<AccessControlAllowOrigin>>;

/// All possible errors.
#[derive(Debug)]
pub enum Error {
	/// Request has failed 
	InvalidCors,
	///
	InvalidRequest,
	/// Error from Hyper.
	Hyper(hyper::Error),
	/// Error from Secret Store.
	SecretStore(parity_secretstore_primitives::error::Error),
}

/// Decomposed HTTP request.
#[derive(Debug)]
pub struct DecomposedRequest {
	/// Request URI.
	pub uri: Uri,
	/// Request method.
	pub method: Method,
	/// ORIGIN header field.
	pub header_origin: Option<String>,
	/// HOST header field.
	pub header_host: Option<String>,
	/// Request body.
	pub body: Vec<u8>,
}

/// Start listening HTTP requests on given address.
pub async fn start_service<KS: KeyServer>(
	listen_address: &str,
	listen_port: u16,
	key_server: Arc<KS>,
	cors: CorsDomains,
) -> Result<(), Error> {
	let cors = Arc::new(cors);
	let http_address = format!("{}:{}", listen_address, listen_port)
		.parse()
		.map_err(|err: std::net::AddrParseError| Error::SecretStore(err.into()))?;
	let http_server = Server::bind(&http_address);
	let http_service_fn = make_service_fn(move |_| {
		let key_server = key_server.clone();
		let cors = cors.clone();
		async move {
			Ok::<_, hyper::Error>(service_fn(
				move |http_request| serve_http_request(
					http_request,
					key_server.clone(),
					cors.clone(),
				)
			))
		}
	});
	let http_service = http_server.serve(http_service_fn);
	http_service.await.map_err(Error::Hyper)
}

/// Serve single HTTP request.
async fn serve_http_request<KS: KeyServer>(
	http_request: Request<Body>,
	key_server: Arc<KS>,
	cors_domains: Arc<CorsDomains>,
) -> Result<Response<Body>, hyper::Error> {
	let decomposed_request = match decompose_http_request(http_request).await {
		Ok(decomposed_request) => decomposed_request,
		Err(error) => return Ok(return_error(error)),
	};

	let allow_cors = match ensure_cors(&decomposed_request, cors_domains) {
		Ok(allow_cors) => allow_cors,
		Err(error) => return Ok(return_error(error)),
	};

	let service_task = match crate::parse::parse_http_request(&decomposed_request) {
		Ok(service_task) => service_task,
		Err(error) => return Ok(return_error(error)),
	};

	let log_secret_store_error = |error| {
		error!(
			target: "secretstore",
			"{} request {} has failed with: {}",
			decomposed_request.method,
			decomposed_request.uri,
			error,
		);

		Error::SecretStore(error)
	};

	match service_task {
		ServiceTask::GenerateServerKey(key_id, requester, threshold) =>
			Ok(return_unencrypted_server_key(
				&decomposed_request,
				allow_cors,
				key_server
					.generate_key(key_id, requester, threshold)
					.await
					.map(|artifacts| artifacts.key)
					.map_err(log_secret_store_error),
			)),
		ServiceTask::RetrieveServerKey(key_id, requester) =>
			Ok(return_unencrypted_server_key(
				&decomposed_request,
				allow_cors,
				key_server
					.restore_key_public(
						key_id,
						requester,
					)
					.await
					.map(|artifacts| artifacts.key)
					.map_err(log_secret_store_error),
			)),
		ServiceTask::GenerateDocumentKey(key_id, requester, threshold) =>
			Ok(return_encrypted_document_key(
				&decomposed_request,
				allow_cors,
				ready(requester.public(&key_id))
					.and_then(|requester_public|
						key_server
							.generate_document_key(key_id, requester, threshold)
							.and_then(move |artifacts| ready(ecies_encrypt(
								&requester_public,
								artifacts.document_key.as_bytes(),
							)))
					)
					.map_err(log_secret_store_error),
			).await),
		ServiceTask::StoreDocumentKey(key_id, requester, common_point, encrypted_point) =>
			Ok(return_empty(
				&decomposed_request,
				allow_cors,
				key_server
					.store_document_key(key_id, requester, common_point, encrypted_point)
					.await
					.map_err(log_secret_store_error),
			)),
		ServiceTask::RetrieveDocumentKey(key_id, requester) =>
			Ok(return_encrypted_document_key(
				&decomposed_request,
				allow_cors,
				ready(requester.public(&key_id))
					.and_then(|requester_public|
						key_server
							.restore_document_key(key_id, requester)
							.and_then(move |artifacts| ready(ecies_encrypt(
								&requester_public,
								artifacts.document_key.as_bytes(),
							)))
					)
					.map_err(log_secret_store_error)
			).await),
		ServiceTask::RetrieveShadowDocumentKey(key_id, requester) =>
			Ok(return_document_key_shadow(
				&decomposed_request,
				allow_cors,
				key_server
					.restore_document_key_shadow(key_id, requester)
					.await
					.map_err(log_secret_store_error),
			)),
		ServiceTask::SchnorrSignMessage(key_id, requester, message_hash) =>
			Ok(return_encrypted_message_signature(
				&decomposed_request,
				allow_cors,
				ready(requester.public(&key_id))
					.and_then(|requester_public|
						key_server
							.sign_message_schnorr(key_id, requester, message_hash)
							.and_then(|artifacts| {
								let mut combined_signature = [0; 64];
								combined_signature[..32].clone_from_slice(artifacts.signature_c.as_bytes());
								combined_signature[32..].clone_from_slice(artifacts.signature_s.as_bytes());
								ready(Ok(combined_signature))
							})
							.and_then(move |plain_signature| ready(ecies_encrypt(
								&requester_public,
								&plain_signature,
							)))
					)
					.map_err(log_secret_store_error)
			).await),
		ServiceTask::EcdsaSignMessage(key_id, requester, message_hash) =>
			Ok(return_encrypted_message_signature(
				&decomposed_request,
				allow_cors,
				ready(requester.public(&key_id))
					.and_then(|requester_public|
						key_server
							.sign_message_ecdsa(key_id, requester, message_hash)
							.and_then(move |artifacts| ready(ecies_encrypt(
								&requester_public,
								&*artifacts.signature,
							)))
					)
					.map_err(log_secret_store_error)
			).await),
		ServiceTask::ChangeServersSet(old_set_signature, new_set_signature, new_set) =>
			Ok(return_empty(
				&decomposed_request,
				allow_cors,
				key_server
					.change_servers_set(old_set_signature, new_set_signature, new_set)
					.await
					.map_err(log_secret_store_error),
			)),
	}
}

/// Decompose single HTTP request.
async fn decompose_http_request(
	http_request: Request<Body>,
) -> Result<DecomposedRequest, Error> {
	let uri = http_request.uri().clone();
	let method = http_request.method().clone();
	let header_origin = http_request
		.headers()
		.get(header::ORIGIN)
		.and_then(|value| value.to_str().ok())
		.map(Into::into);
	let header_host = http_request
		.headers()
		.get(header::HOST)
		.and_then(|value| value.to_str().ok())
		.map(Into::into);
	let body = hyper::body::to_bytes(http_request.into_body())
		.await
		.map_err(|error| {
			error!(
				target: "secretstore",
				"Failed to read body of {}-request {}: {}",
				method,
				uri,
				error,
			);

			Error::Hyper(error)
		})?.to_vec();

	Ok(DecomposedRequest {
		uri,
		method,
		header_origin,
		header_host,
		body,
	})
}

/// Check CORS rules.
fn ensure_cors(
	request: &DecomposedRequest,
	cors_domains: Arc<CorsDomains>,
) -> Result<AllowCors<AccessControlAllowOrigin>, Error> {
	let allow_cors = cors::get_cors_allow_origin(
		request.header_origin.as_ref().map(|s| s.as_ref()),
		request.header_host.as_ref().map(|s| s.as_ref()),
		&*cors_domains,
	);

	match allow_cors {
		AllowCors::Invalid => {
			error!(
				target: "secretstore",
				"Ignoring {}-request {} with unauthorized Origin header",
				request.method,
				request.uri,
			);

			Err(Error::InvalidCors)
		},
		_ => Ok(allow_cors),
	}
}

fn return_empty(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	empty: Result<(), Error>,
) -> Response<Body> {
	return_bytes::<i32>(request, allow_cors, empty.map(|_| None))
}

fn return_unencrypted_server_key(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	result: Result<Public, Error>,
) -> Response<Body> {
	return_bytes(request, allow_cors, result.map(|key| Some(SerializablePublic(key))))
}

async fn return_encrypted_document_key(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	encrypted_document_key: impl Future<Output=Result<Vec<u8>, Error>>,
) -> Response<Body> {
	return_bytes(
		request,
		allow_cors,
		encrypted_document_key
			.await
			.map(|key| Some(SerializableBytes(key))),
	)
}

fn return_document_key_shadow(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	document_key_shadow: Result<DocumentKeyShadowRetrievalArtifacts, Error>,
) -> Response<Body> {
	return_bytes(request, allow_cors, document_key_shadow.map(|k| Some(SerializableEncryptedDocumentKeyShadow {
		decrypted_secret: k.encrypted_document_key.into(),
		common_point: k.common_point.into(),
		decrypt_shadows: k
			.participants_coefficients
			.values()
			.cloned()
			.map(Into::into)
			.collect(),
	})))
}

async fn return_encrypted_message_signature(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	encrypted_signature: impl Future<Output=Result<Vec<u8>, Error>>,
) -> Response<Body> {
	return_bytes(
		request,
		allow_cors,
		encrypted_signature
			.await
			.map(|s| Some(SerializableBytes(s))),
	)
}

fn return_bytes<T: Serialize>(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	result: Result<Option<T>, Error>,
) -> Response<Body> {
	match result {
		Ok(Some(result)) => match serde_json::to_vec(&result) {
			Ok(result) => {
				let body: Body = result.into();
				let mut builder = Response::builder();
				builder = builder.header(
					header::CONTENT_TYPE,
					HeaderValue::from_static("application/json; charset=utf-8"),
				);
				if let AllowCors::Ok(AccessControlAllowOrigin::Value(origin)) = allow_cors {
					builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.to_string());
				}
				builder.body(body).expect("Error creating http response")
			},
			Err(err) => {
				error!(target: "secretstore", "Response to request {} has failed with: {}", request.uri, err);
				Response::builder()
					.status(StatusCode::INTERNAL_SERVER_ERROR)
					.body(Body::empty())
					.expect("Nothing to parse, cannot fail; qed")
			}
		},
		Ok(None) => {
			let mut builder = Response::builder();
			builder = builder.status(StatusCode::OK);
			if let AllowCors::Ok(AccessControlAllowOrigin::Value(origin)) = allow_cors {
				builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.to_string());
			}
			builder.body(Body::empty()).expect("Nothing to parse, cannot fail; qed")
		},
		Err(err) => return_error(err),
	}
}

fn return_error(err: Error) -> Response<Body> {
	let status = match err {
		Error::SecretStore(SecretStoreError::AccessDenied)
		| Error::SecretStore(SecretStoreError::ConsensusUnreachable)
		| Error::SecretStore(SecretStoreError::ConsensusTemporaryUnreachable) =>
			StatusCode::FORBIDDEN,
		| Error::SecretStore(SecretStoreError::ServerKeyIsNotFound)
		| Error::SecretStore(SecretStoreError::DocumentKeyIsNotFound) =>
			StatusCode::NOT_FOUND,
		Error::InvalidCors
		| Error::InvalidRequest
		| Error::SecretStore(SecretStoreError::InsufficientRequesterData(_))
		| Error::Hyper(_)
		| Error::SecretStore(SecretStoreError::Hyper(_))
		| Error::SecretStore(SecretStoreError::Serde(_))
		| Error::SecretStore(SecretStoreError::DocumentKeyAlreadyStored)
		| Error::SecretStore(SecretStoreError::ServerKeyAlreadyGenerated) =>
			StatusCode::BAD_REQUEST,
		_ => StatusCode::INTERNAL_SERVER_ERROR,
	};

	let mut res = Response::builder();
	res = res.status(status);

	// return error text. ignore errors when returning error
	let error_text = format!("\"{}\"", err);
	if let Ok(error_text) = serde_json::to_vec(&error_text) {
		res = res.header(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
		res.body(error_text.into())
			.expect("`error_text` is a formatted string, parsing cannot fail; qed")
	} else {
		res.body(Body::empty())
			.expect("Nothing to parse, cannot fail; qed")
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		match *self {
			Error::InvalidCors => write!(f, "Request with unauthorized Origin header"),
			Error::InvalidRequest => write!(f, "Failed to parse request"),
			Error::Hyper(ref error) => write!(f, "Internal server error: {}", error),
			Error::SecretStore(ref error) => write!(f, "Secret store error: {}", error),
		}
	}
}
