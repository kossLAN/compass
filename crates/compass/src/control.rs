use std::io;
use std::path::PathBuf;

use compass_proto::{
    ExitNodeChoice, IpcRequest, IpcResponse, MAX_IPC_LINE, RecordEntry, StatusReport,
};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("connecting to compassd at {}: {error} (is it running?)", socket.display())]
    Connect { socket: PathBuf, error: io::Error },
    #[error("talking to compassd: {0}")]
    Transport(LinesCodecError),
    #[error("compassd closed the connection")]
    Closed,
    #[error("compassd sent an invalid response: {0}")]
    Invalid(serde_json::Error),
    #[error("{0}")]
    Failed(String),
    #[error("compassd sent an unexpected response")]
    Unexpected,
}

#[derive(Debug, Clone)]
pub struct Control {
    socket: PathBuf,
}

impl Control {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub async fn status(&self) -> Result<StatusReport, ControlError> {
        match self.call(&IpcRequest::Status).await? {
            IpcResponse::Status(report) => Ok(*report),
            other => Err(unexpected(other)),
        }
    }

    pub async fn records(&self) -> Result<Vec<RecordEntry>, ControlError> {
        match self.call(&IpcRequest::DnsList).await? {
            IpcResponse::Records { records } => Ok(records),
            other => Err(unexpected(other)),
        }
    }

    pub async fn set_exit_node(
        &self,
        choice: ExitNodeChoice,
    ) -> Result<StatusReport, ControlError> {
        match self.call(&IpcRequest::SetExitNode(choice)).await? {
            IpcResponse::Status(report) => Ok(*report),
            other => Err(unexpected(other)),
        }
    }

    async fn call(&self, request: &IpcRequest) -> Result<IpcResponse, ControlError> {
        let stream =
            UnixStream::connect(&self.socket)
                .await
                .map_err(|error| ControlError::Connect {
                    socket: self.socket.clone(),
                    error,
                })?;
        let mut lines = Framed::new(stream, LinesCodec::new_with_max_length(MAX_IPC_LINE));
        let request = serde_json::to_string(request).expect("IPC requests always serialize");
        lines.send(request).await.map_err(ControlError::Transport)?;
        let line = lines
            .next()
            .await
            .ok_or(ControlError::Closed)?
            .map_err(ControlError::Transport)?;
        serde_json::from_str(&line).map_err(ControlError::Invalid)
    }
}

fn unexpected(response: IpcResponse) -> ControlError {
    match response {
        IpcResponse::Failed { message } => ControlError::Failed(message),
        _ => ControlError::Unexpected,
    }
}
