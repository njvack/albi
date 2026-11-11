import Foundation
import NetworkExtension

// A system extension's entry point: hand control to NetworkExtension.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
