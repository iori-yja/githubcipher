module PubKey where
import Data.List
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Codec.Crypto.RSA as RSA

makePubKey :: ((Int, Int), Integer, Integer) -> RSA.PublicKey
makePubKey ((nsz, _), e, n) = RSA.PublicKey (nsz - 1) n e

decodePubKey :: T.Text -> ((Int, Int), Integer, Integer)
decodePubKey text = let Right key =  keybin text
                        algosz = bytesToInt $ BS.take 4 key
                        algo = (BS.take algosz . BS.drop 4) key
                        take4from i = BS.take 4 . BS.drop i $ key
                        esize = bytesToInt $ take4from (algosz + 4)
                        nsize = bytesToInt $ take4from (esize + algosz + 4 + 4)
                        get_e = BS.take esize . BS.drop (4 + algosz + 4)
                        get_n = BS.take nsize . BS.drop (4 + algosz + 4 + esize + 4)
                        in
                        ((nsize, esize), toInteger . bytesToInt $ get_e key, bytesToInteger $ get_n key)
                        where
                            bytesToInt :: BS.ByteString -> Int
                            bytesToInt = (foldl' (\z n -> (z * 256) + fromIntegral n) 0) . BS.unpack
                            bytesToInteger :: BS.ByteString -> Integer
                            bytesToInteger = (foldl' (\z n -> (z * 256) + fromIntegral n) 0) . BS.unpack
                            keybin = B64.decode . TE.encodeUtf8 . head . tail . (T.splitOn $ T.pack " ")

