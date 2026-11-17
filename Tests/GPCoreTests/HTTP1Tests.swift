import Testing
@testable import GPCore

@Suite struct HTTP1Tests {
    func parse(_ s: String, splitEvery n: Int = 0, eof: Bool = false) throws -> HTTPResponse? {
        var p = HTTP1.ResponseParser()
        let bytes = Array(s.utf8)
        if n > 0 {
            var i = 0
            while i < bytes.count {
                if let r = try p.feed(Array(bytes[i..<min(i + n, bytes.count)])) { return r }
                i += n
            }
        } else if let r = try p.feed(bytes) {
            return r
        }
        return eof ? try p.finish() : nil
    }

    @Test func encodesPost() {
        let r = HTTPRequest(path: "/ssl-vpn/getconfig.esp", body: ["a": "b c"])
        let s = String(decoding: HTTP1.encode(r, host: "gw.example.edu:8443"), as: UTF8.self)
        #expect(s.hasPrefix("POST /ssl-vpn/getconfig.esp HTTP/1.1\r\nHost: gw.example.edu:8443\r\n"))
        #expect(s.contains("User-Agent: PAN GlobalProtect\r\n"))
        #expect(s.contains("Content-Type: application/x-www-form-urlencoded\r\n"))
        #expect(s.hasSuffix("Content-Length: 5\r\n\r\na=b%20c"))
    }

    @Test func encodesGet() {
        let r = HTTPRequest(method: "GET", path: "/x", body: [:])
        let s = String(decoding: HTTP1.encode(r, host: "h"), as: UTF8.self)
        #expect(!s.contains("Content-Length"))
        #expect(s.hasSuffix("Connection: close\r\n\r\n"))
    }

    @Test func contentLength() throws {
        let s = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 7\r\n\r\n<a>1</a>extra"
        #expect(try parse(s) == HTTPResponse(status: 200, body: "<a>1</a"))
        #expect(try parse(s, splitEvery: 3) == HTTPResponse(status: 200, body: "<a>1</a"))
    }

    @Test func chunked() throws {
        let s = "HTTP/1.1 512 Custom error\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab\r\n\r\n3;x=y\r\ncde\r\n0\r\n\r\n"
        #expect(try parse(s) == HTTPResponse(status: 512, body: "ab\r\ncde"))
        #expect(try parse(s, splitEvery: 1) == HTTPResponse(status: 512, body: "ab\r\ncde"))
    }

    @Test func untilClose() throws {
        let s = "HTTP/1.0 200 OK\r\nServer: x\r\n\r\nhello"
        #expect(try parse(s) == nil)
        #expect(try parse(s, eof: true) == HTTPResponse(status: 200, body: "hello"))
    }

    @Test func skipsContinue() throws {
        let s = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        #expect(try parse(s) == HTTPResponse(status: 200, body: "ok"))
    }

    @Test func truncated() {
        #expect(throws: HTTP1.ParseError.truncated) {
            try parse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", eof: true)
        }
        #expect(throws: HTTP1.ParseError.truncated) { try parse("HTTP/1.1 200", eof: true) }
    }

    @Test func badStatus() {
        #expect(throws: HTTP1.ParseError.badStatusLine) { try parse("SSH-2.0-x\r\n\r\n") }
    }
}
