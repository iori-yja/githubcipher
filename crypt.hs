{-# LANGUAGE OverloadedStrings, PackageImports #-}
import System.Environment
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy.Char8 as B
import Network.Wreq
import Control.Applicative
import Control.Lens
import Data.Maybe
import Data.Aeson.Types
import Data.Aeson.Lens
import Data.Word
import Data.List
import "crypto-random" Crypto.Random
import qualified Crypto.Random.AESCtr as RA
import Crypto.Cipher.AES
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import EncryptKey

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

encryptFile :: IO (AESIV, RA.AESRNG) -> IO AES -> IO (BS.ByteString -> BS.ByteString)
encryptFile iv cc = fmap runencrypt cc <*> fmap fst iv
    where
    runencrypt c iv = encryptCBC c iv

main :: IO()
main = do
    sfname' <- sfname
    fmap (V.map decodePubKey) (getKeys =<< username) >>=
        V.mapM (\k -> encryptKey k $ (fst initVec, fst ciphercontext)) >>=
            kwriter sfname' . show >>
                encryptFile initVec ciphercontext <*> sourcefile >>= bwriter sfname'
    where
    initVec = (over _1 aesIV_ . cprgGenerate 16) <$> RA.makeSystem
    ciphercontext = initAES . fst <$> (cprgGenerate 32 . snd) <$> initVec
    username = head <$> getArgs
    sfname = (head . tail) <$> getArgs
    sourcefile = BS.readFile =<< sfname
    bwriter fname = BS.writeFile (fname ++ ".enc")
    kwriter fname = writeFile (fname ++ ".key")

