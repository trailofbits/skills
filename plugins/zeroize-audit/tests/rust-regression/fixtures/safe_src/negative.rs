// Safe code with no dangerous API patterns.
// All operations on non-sensitive types using safe, approved APIs.

struct TelemetryPacket {
    payload: Vec<u8>,
}

fn process(p: TelemetryPacket) {
    drop(p);
}

fn copy_data(src: &[u8]) -> Vec<u8> {
    src.to_vec()
}
