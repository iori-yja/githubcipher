{-# LANGUAGE OverloadedStrings #-}
import Prelude
import Network.Wreq
import System.Environment
import qualified Data.ByteString.Lazy.Char8 as B
import Control.Lens

getbody :: Response B.ByteString -> B.ByteString
getbody r | r ^. responseStatus . statusCode == 200 = r ^. responseBody
            | otherwise = "NG"

main :: IO()
main = let username = fmap head getArgs
           targetfile = fmap (head . tail) getArgs
           githubAPIurl u =
               "https://api.github.com/users/" ++ u ++ "/keys"
           in
           targetfile >>= (\n -> username >>=
               get . githubAPIurl >>=
                   (B.writeFile n) . getbody)


