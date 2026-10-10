import AppKit
import CoreImage

enum QRCodeImage {
    /// Renders a QR code for `text` as a crisp, scalable NSImage.
    static func make(from text: String) -> NSImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(text.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")

        guard let output = filter.outputImage else { return nil }
        let scale = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))

        let rep = NSCIImageRep(ciImage: scale)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        image.isTemplate = false
        return image
    }
}
