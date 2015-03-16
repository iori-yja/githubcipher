{-# LANGUAGE OverloadedStrings #-}
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
import Crypto.Random
import qualified Crypto.Random.AESCtr as RA
import Crypto.Cipher.AES
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V

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

decodePubKey :: T.Text -> ((Int, Int), [Word8], [Word8])
decodePubKey text = let Right key =  keybin text
                        algosz = getKeysize $ BS.take 4 key
                        algo = (BS.take algosz . BS.drop 4) key
                        take4from i = BS.take 4 . BS.drop i $ key
                        esize = getKeysize $ take4from (algosz + 4)
                        nsize = getKeysize $ take4from (esize + algosz + 8)
                        in
                        ((nsize, esize), BS.unpack $ take4from (algosz + 4), BS.unpack key)
                        where
                            getKeysize :: BS.ByteString -> Int
                            getKeysize = (foldl' (\z n -> (z * 256) + fromIntegral n) 0) . BS.unpack
                            keybin = B64.decode . TE.encodeUtf8 . head . tail . (T.splitOn $ T.pack " ")

main :: IO()
main = do (username:targetfile:_) <- getArgs
          fmap (V.map decodePubKey) (getKeys username) >>= (writeFile (targetfile ++ ".enc")) . show
          where
          initVec = (over _1 aesIV_ . cprgGenerate 128) <$> RA.makeSystem
          ciphercontext = initAES . fst <$> (cprgGenerate (32 * 8) . snd) <$> initVec
          runencrypt c iv = encryptCBC c iv

