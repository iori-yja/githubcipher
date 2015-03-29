{-# LANGUAGE OverloadedStrings, PackageImports #-}
import System.Environment
import Network.Wreq
import Control.Applicative
import Control.Lens
import Data.Maybe
import Data.Word
import Data.List.Lens
import Data.ASN1.Error
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import qualified Data.Text as T
import qualified Data.Text.IO as TI
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Lazy.Char8 as B
import "crypto-random" Crypto.Random
import qualified "crypto-api" Crypto.Random as CR
import qualified Crypto.Random.AESCtr as RA
import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as RSA
import PubKey

data ParseState = BEGIN ParseState
                | ENCED ParseState ParseState
                | AES B.ByteString
                | BIN B.ByteString
                | RAW [ASN1]
                | KEY RSA.PrivateKey
                | END
                | Z
                | Error ParseState
                deriving (Eq, Show)

beginmarker = B.pack "-----BEGIN RSA PRIVATE KEY-----"
endmarker = B.pack "-----END RSA PRIVATE KEY-----"

parsePrivKey :: T.Text -> B.ByteString -> ParseState
parsePrivKey pub file = let keylines = B.lines file
                            in
                            foldr keyparser Z keylines
    where
    keyparser :: B.ByteString -> ParseState -> ParseState
    keyparser "" state = state
    keyparser str END = BIN str
    keyparser _ a@(BEGIN _) = a
    keyparser str   Z   | str == endmarker   = END
    keyparser str state | str == beginmarker = BEGIN $ dec' state
                        | isDEKStatement str =
                            let algo = B.unpack.head.tail $ B.words str
                                iv   = B.pack <$> algo ^? prefixed "AES-128-CBC,"
                                in case iv of
                                        Nothing -> Error state
                                        Just iv' -> ENCED (AES iv') (dec' state)
                        | otherwise =
                            case state of
                                 BIN str1 -> BIN (B.append str str1)
                                 otherwise -> Error state
    isDEKStatement s = (head . B.words) s == B.pack "DEK-Info:"
    dec' (BIN str)   = case B64.decode str of
                            Left a  -> Error (BIN str)
                            Right a -> case decodeASN1 DER a of
                                            Left a -> Error (BIN str)
                                            Right a -> KEY (makeprivkey pub a)
    dec' a = a

makeprivkey :: T.Text -> [ASN1] -> RSA.PrivateKey
makeprivkey pub priv = let IntVal d     = priv !! 4
                           IntVal p    = priv !! 5
                           IntVal q    = priv !! 6
                           IntVal dP   = priv !! 7
                           IntVal dQ   = priv !! 8
                           IntVal qinv = priv !! 9
                           in RSA.PrivateKey ((makePubKey . decodePubKey) pub) d p q dP dQ qinv

getKey :: FilePath -> IO ParseState
getKey fp = parsePrivKey <$> TI.readFile (fp ++ ".pub") <*> B.readFile fp

encryptFile :: IO (BS.ByteString, RA.AESRNG) -> IO BS.ByteString -> IO (BS.ByteString -> BS.ByteString)
encryptFile iv cc = fmap (runencrypt . initAES) cc <*> fmap (aesIV_ . fst) iv
    where
    runencrypt c iv = encryptCTR c iv

main :: IO()
main = do
    sfname' <- sfname
    (getKey =<< privkey) >>= kwriter sfname' . show
    where
    initVec = cprgGenerate 16 <$> RA.makeSystem
    ciphercontext = fst <$> (cprgGenerate 32 . snd) <$> initVec
    privkey = head <$> getArgs
    sfname = (head . tail) <$> getArgs
    sourcedata = BS.readFile =<< sfname
    bwriter fname = BS.writeFile (fname ++ ".enc")
    kwriter fname = writeFile (fname ++ ".key")

