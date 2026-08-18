//
// Copyright 2026 The LogCabin Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! A host gRPC server for testing the Oak Log Cabin Endorser enclave app.
//!
//! This is basically a gRPC shim over the enclave app: it exposes a gRPC
//! server that relays all requests to the enclave app Micro RPC service and
//! translates back responses.

use clap::Parser;
use endorser_grpc_service::logcabin::proto::{
    endorser_service_server::{
        EndorserService as GrpcEndorserService, EndorserServiceServer as GrpcEndorserServer,
    },
    ActivateEndorserRequest, ActivateEndorserResponse, AppendEntryRequest, AppendEntryResponse,
    CreateEndorserRequest, CreateLedgerRequest, CreateLedgerResponse, Endorser as EndorserProto,
    FinalizeEndorserRequest, FinalizeEndorserResponse, GetEndorserRequest, GetEvidenceRequest,
    GetEvidenceResponse, ListEndorsersRequest, ListEndorsersResponse, ReadLatestRequest,
    ReadLatestResponse,
};
use endorser_micro_rpc_service::logcabin::proto::EndorserServiceAsyncClient as EndorserMicroRpcClient;
use oak_launcher_utils::channel::ConnectorHandle;
use tonic::{transport::Server, Request, Response, Status};

#[derive(Parser, Debug)]
struct Args {
    #[clap(flatten)]
    launcher_params: oak_launcher_utils::launcher::Params,

    /// Port to listen on for gRPC requests.
    #[clap(long, default_value = "50051")]
    port: u16,
}

struct GrpcEndorserServiceImpl {
    enclave_handle: ConnectorHandle,
}

/// Converts a protobuf message from one type to another via serialization.
/// Proto message types must be binary compatible.
fn convert_message<SourceType, TargetType>(source: &SourceType) -> Result<TargetType, Status>
where
    SourceType: prost::Message,
    TargetType: prost::Message + Default,
{
    let mut buf = Vec::new();
    source
        .encode(&mut buf)
        .map_err(|e| Status::internal(format!("failed to encode: {}", e)))?;
    TargetType::decode(buf.as_slice())
        .map_err(|e| Status::internal(format!("failed to decode: {}", e)))
}

/// Maps a micro_rpc status to a tonic status, preserving the status code.
fn to_grpc_status(status: micro_rpc::Status) -> Status {
    let code = match status.code {
        micro_rpc::StatusCode::Ok => tonic::Code::Ok,
        micro_rpc::StatusCode::Cancelled => tonic::Code::Cancelled,
        micro_rpc::StatusCode::Unknown => tonic::Code::Unknown,
        micro_rpc::StatusCode::InvalidArgument => tonic::Code::InvalidArgument,
        micro_rpc::StatusCode::DeadlineExceeded => tonic::Code::DeadlineExceeded,
        micro_rpc::StatusCode::NotFound => tonic::Code::NotFound,
        micro_rpc::StatusCode::AlreadyExists => tonic::Code::AlreadyExists,
        micro_rpc::StatusCode::PermissionDenied => tonic::Code::PermissionDenied,
        micro_rpc::StatusCode::ResourceExhausted => tonic::Code::ResourceExhausted,
        micro_rpc::StatusCode::FailedPrecondition => tonic::Code::FailedPrecondition,
        micro_rpc::StatusCode::Aborted => tonic::Code::Aborted,
        micro_rpc::StatusCode::OutOfRange => tonic::Code::OutOfRange,
        micro_rpc::StatusCode::Unimplemented => tonic::Code::Unimplemented,
        micro_rpc::StatusCode::Internal => tonic::Code::Internal,
        micro_rpc::StatusCode::Unavailable => tonic::Code::Unavailable,
        micro_rpc::StatusCode::DataLoss => tonic::Code::DataLoss,
        micro_rpc::StatusCode::Unauthenticated => tonic::Code::Unauthenticated,
    };
    Status::new(code, status.message)
}

#[tonic::async_trait]
impl GrpcEndorserService for GrpcEndorserServiceImpl {
    async fn get_evidence(
        &self,
        request: Request<GetEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        let grpc_req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::GetEvidenceRequest =
            convert_message(&grpc_req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .get_evidence(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: GetEvidenceResponse = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }

    async fn create_endorser(
        &self,
        request: Request<CreateEndorserRequest>,
    ) -> Result<Response<EndorserProto>, Status> {
        let grpc_req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::CreateEndorserRequest =
            convert_message(&grpc_req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .create_endorser(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: EndorserProto = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }

    async fn list_endorsers(
        &self,
        request: Request<ListEndorsersRequest>,
    ) -> Result<Response<ListEndorsersResponse>, Status> {
        let grpc_req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::ListEndorsersRequest =
            convert_message(&grpc_req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .list_endorsers(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: ListEndorsersResponse = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }

    async fn get_endorser(
        &self,
        request: Request<GetEndorserRequest>,
    ) -> Result<Response<EndorserProto>, Status> {
        let grpc_req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::GetEndorserRequest =
            convert_message(&grpc_req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .get_endorser(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: EndorserProto = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }

    async fn activate_endorser(
        &self,
        request: Request<ActivateEndorserRequest>,
    ) -> Result<Response<ActivateEndorserResponse>, Status> {
        let req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::ActivateEndorserRequest =
            convert_message(&req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .activate_endorser(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: ActivateEndorserResponse = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }

    async fn create_ledger(
        &self,
        request: Request<CreateLedgerRequest>,
    ) -> Result<Response<CreateLedgerResponse>, Status> {
        let req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::CreateLedgerRequest =
            convert_message(&req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .create_ledger(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: CreateLedgerResponse = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }

    async fn append_entry(
        &self,
        request: Request<AppendEntryRequest>,
    ) -> Result<Response<AppendEntryResponse>, Status> {
        let req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::AppendEntryRequest =
            convert_message(&req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .append_entry(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: AppendEntryResponse = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }

    async fn read_latest(
        &self,
        request: Request<ReadLatestRequest>,
    ) -> Result<Response<ReadLatestResponse>, Status> {
        let req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::ReadLatestRequest =
            convert_message(&req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .read_latest(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: ReadLatestResponse = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }

    async fn finalize_endorser(
        &self,
        request: Request<FinalizeEndorserRequest>,
    ) -> Result<Response<FinalizeEndorserResponse>, Status> {
        let req = request.into_inner();
        let micro_rpc_req: endorser_micro_rpc_service::logcabin::proto::FinalizeEndorserRequest =
            convert_message(&req)?;

        let mut client = EndorserMicroRpcClient::new(self.enclave_handle.clone());
        let resp = client
            .finalize_endorser(&micro_rpc_req)
            .await
            .flatten()
            .map_err(to_grpc_status)?;

        let tonic_resp: FinalizeEndorserResponse = convert_message(&resp)?;
        Ok(Response::new(tonic_resp))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    log::info!("Launching VM...");
    let (launched_instance, enclave_handle) =
        oak_launcher_utils::launcher::launch(args.launcher_params)
            .await
            .map_err(|e| anyhow::anyhow!("failed to launch VM: {:?}", e))?;

    let addr_string = format!("[::1]:{}", args.port);
    log::info!(
        "VM launched. Starting host gRPC server on {}...",
        addr_string
    );

    let addr: std::net::SocketAddr = addr_string.parse()?;
    let service = GrpcEndorserServiceImpl { enclave_handle };

    Server::builder()
        .add_service(GrpcEndorserServer::new(service))
        .serve(addr)
        .await?;

    launched_instance.kill().await?;
    Ok(())
}
