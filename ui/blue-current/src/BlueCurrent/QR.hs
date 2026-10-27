module BlueCurrent.QR (qrPixels) where

import qualified Codec.QRCode as QR
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Vector.Unboxed as V

-- Four-module quiet zone and integer scaling keep real receive codes scannable.
qrPixels :: Text -> Maybe (Int, BS.ByteString)
qrPixels address = do
  qr <- QR.encodeText (QR.defaultQRCodeOptions QR.M) QR.Iso8859_1 address
  let modules = QR.qrImageSize qr
      side = (modules + 8) * 4
      pixels = QR.qrImageData qr
      black x y = let mx = x `div` 4 - 4; my = y `div` 4 - 4
                  in mx >= 0 && my >= 0 && mx < modules && my < modules && pixels V.! (my * modules + mx)
      rgba x y = if black x y then [0,0,0,255] else [255,255,255,255]
  pure (side, BS.pack (concat [rgba x y | y <- [0..side-1], x <- [0..side-1]]))
