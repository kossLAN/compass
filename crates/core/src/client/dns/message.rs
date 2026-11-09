use bytes::{Buf as _, BufMut as _, BytesMut};
use hickory_server::proto::op::{Message, MessageType, Metadata, ResponseCode};
use hickory_server::proto::rr::{LowerName, Record};

use super::zone::{Answer, Zone};

pub enum Reply {
    Answer(Vec<u8>),
    Forward,
}

pub fn answer(zone: &Zone, query: &[u8]) -> Option<Reply> {
    let request = query_message(query)?;

    let [question] = request.queries.as_slice() else {
        return respond(&request, ResponseCode::FormErr, Vec::new()).map(Reply::Answer);
    };

    let (code, records) =
        match zone.lookup(&LowerName::from(question.name()), question.query_type()) {
            Answer::Refused => return Some(Reply::Forward),
            Answer::NotFound => (ResponseCode::NXDomain, Vec::new()),
            Answer::Found(records) => (ResponseCode::NoError, records),
        };

    respond(&request, code, records).map(Reply::Answer)
}

pub fn failure(query: &[u8]) -> Option<Vec<u8>> {
    respond(&query_message(query)?, ResponseCode::ServFail, Vec::new())
}

fn query_message(query: &[u8]) -> Option<Message> {
    Message::from_vec(query)
        .ok()
        .filter(|message| message.metadata.message_type == MessageType::Query)
}

fn respond(request: &Message, code: ResponseCode, answers: Vec<Record>) -> Option<Vec<u8>> {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = code != ResponseCode::ServFail;
    metadata.response_code = code;

    let mut response = Message::response(metadata.id, metadata.op_code);
    response.metadata = metadata;
    response.add_queries(request.queries.iter().cloned());
    response.add_answers(answers);
    response.to_vec().ok()
}

pub fn frame(message: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(message.len()).ok()?;
    let mut framed = Vec::with_capacity(2 + message.len());
    framed.put_u16(len);
    framed.put_slice(message);
    Some(framed)
}

pub fn unframe(stream: &mut BytesMut) -> Option<Vec<u8>> {
    let len = usize::from(stream.get(..2)?.get_u16());

    if stream.len() < 2 + len {
        return None;
    }

    stream.advance(2);
    Some(stream.split_to(len).to_vec())
}
