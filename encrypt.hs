{-# LANGUAGE OverloadedStrings, PackageImports #-}
import System.Environment
import Network.Wreq
import Control.Applicative
import Control.Lens
import Data.Maybe
import Data.Aeson.Types
import Data.Aeson.Lens
import Data.Word
import Data.List
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy.Char8 as B
import "crypto-random" Crypto.Random
import qualified "crypto-api" Crypto.Random as CR
import qualified Crypto.Random.AESCtr as RA
import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as RSA
import PubKey

encryptBS :: RSA.PublicKey -> (IO BS.ByteString, IO BS.ByteString) -> IO B.ByteString
encryptBS pk (iv,k) = do g <- CR.newGenIO :: IO CR.SystemRandom
                         iv' <- iv
                         k' <- k
                         let encer gen = RSA.encrypt g pk
                             ivenc = encer g (B.fromStrict iv')
                             kenc = encer (snd ivenc) (B.fromStrict k')
                             in return (B.append (fst ivenc) (fst kenc))

encryptKey :: (IO BS.ByteString, IO BS.ByteString)
                ->((Int, Int), Integer, Integer)
                -> IO B.ByteString
encryptKey a k = encryptBS (makePubKey k) a

listKeys :: Response B.ByteString -> Maybe (V.Vector T.Text)
listKeys r
    | r ^. responseStatus . statusCode /= 200 = Nothing
    | otherwise = fmap (V.filter (\a -> T.length a /= 0) . V.map dum . V.map getKey) resBody
                where
                    getKey = (\a -> a ^? (key . T.pack) "key")
                    dum (Just (String a)) = a
                    dum _ = T.empty
                    resBody = (r ^. responseBody ^? _Array)


getKeys :: String -> IO(V.Vector T.Text)
getKeys username = putStrLn ("Connecting to " ++ gurl username ++ "...") >>
    dum . listKeys <$> (get $ gurl username)
    where
    gurl u       = "https://api.github.com/users/" ++ u ++ "/keys"
    dum Nothing  = V.empty
    dum (Just a) = a

encryptFile :: IO (BS.ByteString, RA.AESRNG) -> IO BS.ByteString -> IO (BS.ByteString -> BS.ByteString)
encryptFile iv cc = fmap (runencrypt . initAES) cc <*> fmap (aesIV_ . fst) iv
    where
    runencrypt c iv = encryptCTR c iv

main :: IO()
main = do
    sfname' <- sfname
    fmap (V.map decodePubKey) (getKeys =<< username) >>=
        V.mapM (encryptKey (fmap fst initVec, ciphercontext)) >>=
            kwriter sfname' . show >>
                encryptFile initVec ciphercontext <*> sourcedata >>= bwriter sfname'
    where
    initVec = cprgGenerate 16 <$> RA.makeSystem
    ciphercontext = fst <$> (cprgGenerate 32 . snd) <$> initVec
    username = head <$> getArgs
    sfname = (head . tail) <$> getArgs
    sourcedata = BS.readFile =<< sfname
    bwriter fname = BS.writeFile (fname ++ ".enc")
    kwriter fname = writeFile (fname ++ ".key")

