// Writes this directory's archives with Foundation's NSKeyedArchiver:
//   swift tests/fixtures/nskeyedarchiver/generate.swift tests/fixtures/nskeyedarchiver
import Foundation

let dir = URL(fileURLWithPath: CommandLine.arguments[1])

/// Stands in for XCTest's XCTCapabilities, which encodes one dictionary.
class Capabilities: NSObject, NSCoding {
    let caps: NSDictionary
    init(_ caps: NSDictionary) { self.caps = caps }
    required init?(coder: NSCoder) { nil }
    func encode(with c: NSCoder) { c.encode(caps, forKey: "capabilities-dictionary") }
}

func write(_ name: String, _ root: Any, xml: Bool = false) throws {
    let a = NSKeyedArchiver(requiringSecureCoding: false)
    if xml { a.outputFormat = .xml }
    a.setClassName("XCTCapabilities", for: Capabilities.self)
    a.encode(root, forKey: NSKeyedArchiveRootObjectKey)
    a.finishEncoding()
    try a.encodedData.write(to: dir.appendingPathComponent(name))
}

let primitives: NSArray = [
    NSNumber(value: 1), NSNumber(value: -7), NSNumber(value: 1.5), true, false, "Hello, World!",
    "rios".data(using: .utf8)!, NSNumber(value: Int64.max), NSNumber(value: UInt64.max),
]
let collections: NSDictionary = [
    "array": [true, "a", 42] as NSArray,
    "nested": [[1], [2, [3]]] as NSArray,
    "set": NSSet(object: 5),
    "mutable": NSMutableString(string: "m"),
    "null": NSNull(),
    "date": Date(timeIntervalSinceReferenceDate: 1000.5),
    "uuid": UUID(uuidString: "4588D2DB-2340-6C41-BE63-4596C6AE7FE3")!,
]
for xml in [false, true] {
    let ext = xml ? "xml" : "bin"
    try write("primitives.\(ext)", primitives, xml: xml)
    try write("collections.\(ext)", collections, xml: xml)
}
try write("null.bin", NSNull())
try write("uuid.bin", UUID(uuidString: "4588D2DB-2340-6C41-BE63-4596C6AE7FE3")!)
try write("strings.bin", ["a", "n", "c"] as NSArray)
try write("empty-array.bin", [] as NSArray)
try write("url.bin", NSURL(string: "PlugIns/R.xctest", relativeTo: URL(string: "file:///var/R.app/"))!)
try write("error.bin", NSError(domain: "com.example", code: 7, userInfo: [NSLocalizedDescriptionKey: "boom"]))
try write("uint64-keys.bin", [NSNumber(value: UInt64.max): "max", NSNumber(value: 1): "one"] as NSDictionary)
try write("value.bin", NSValue(range: NSRange(location: 1, length: 2)))
try write("capabilities.bin", Capabilities(["expected failure test capability": 1, "test timeout capability": 1]))
