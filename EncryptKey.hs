{-# LANGUAGE OverloadedStrings, PackageImports #-}

module EncryptKey where
import qualified Data.ByteString.Lazy as B
import Control.Applicative
import "crypto-api" Crypto.Random
import qualified Data.Vector as V
import qualified Codec.Crypto.RSA as RSA

makePubKey :: ((Int, Int), Integer, Integer) -> RSA.PublicKey
makePubKey ((nsz, _), e, n) = RSA.PublicKey nsz n e

encryptBS :: RSA.PublicKey -> (IO B.ByteString, IO B.ByteString) -> IO B.ByteString
encryptBS pk (iv,k) = do g <- newGenIO :: IO SystemRandom
                         iv' <- iv
                         k' <- k
                         let encer gen = RSA.encrypt g pk
                             ivenc = encer g iv'
                             kenc = encer (snd ivenc) k'
                             in return (B.append (fst ivenc) (fst kenc))

encryptKey :: ((Int, Int), Integer, Integer)
                -> (IO B.ByteString, IO B.ByteString)
                -> IO B.ByteString
encryptKey k a = encryptBS (makePubKey k) a

