{-# LANGUAGE OverloadedStrings, PackageImports #-}

module EncryptKey where
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as B
import Control.Applicative
import qualified "crypto-api" Crypto.Random as CR
import qualified Data.Vector as V
import qualified Codec.Crypto.RSA as RSA

makePubKey :: ((Int, Int), Integer, Integer) -> RSA.PublicKey
makePubKey ((nsz, _), e, n) = RSA.PublicKey (nsz - 1) n e

encryptBS :: RSA.PublicKey -> (IO BS.ByteString, IO BS.ByteString) -> IO B.ByteString
encryptBS pk (iv,k) = do g <- CR.newGenIO :: IO CR.SystemRandom
                         iv' <- iv
                         k' <- k
                         let encer gen = RSA.encrypt g pk
                             ivenc = encer g (B.fromStrict iv')
                             kenc = encer (snd ivenc) (B.fromStrict k')
                             in return (B.append (fst ivenc) (fst kenc))

encryptKey :: ((Int, Int), Integer, Integer)
                -> (IO BS.ByteString, IO BS.ByteString)
                -> IO B.ByteString
encryptKey k a = encryptBS (makePubKey k) a

