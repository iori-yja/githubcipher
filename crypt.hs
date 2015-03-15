{-# LANGUAGE OverloadedStrings #-}
import Prelude
import System.Environment
import qualified Data.ByteString.Lazy.Char8 as B
import Network.Wreq
import Control.Applicative
import Control.Lens
import Data.Maybe
import Data.Aeson.Types
import Data.Aeson.Lens
import Crypto.Random
import qualified Crypto.Random.AESCtr as RA
import qualified Data.Text as T
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

--(B.pack . show) (fmap ((\a -> a ^? (key . T.pack) "key") . V.head) (r ^. responseBody ^? _Array))
main :: IO()
main = do (username:targetfile:_) <- getArgs
          rangen <- RA.makeSystem
          putStrLn ("Connecting to " ++ gurl username ++ "...") >>
              (B.pack . show . listKeys) <$> (get $ gurl username) >>= B.writeFile targetfile
          where
          gurl u = "https://api.github.com/users/" ++ u ++ "/keys"


