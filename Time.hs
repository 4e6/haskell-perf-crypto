{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Main (main) where

import           Control.DeepSeq
import           Control.Monad.State.Strict
import           Criterion.Main
import           Criterion.Types
import qualified Crypto.Cipher.AES
import qualified Crypto.Cipher.Types
import qualified Crypto.Error
import qualified Crypto.Random
import           Data.ByteString (ByteString)
import qualified OpenSSL.EVP.Cipher

type Env = (ByteString, ByteString, ByteString, OpenSSL.EVP.Cipher.Cipher)

main :: IO ()
main = defaultMainWith
  defaultConfig { csvFile = Just "out.csv" }
  [ env (setupEnv 16 16 1024) $ \ ~(k,i,v,c) -> bgroup "AES-128-CBC"
    [ bench "cryptonite" $ nf (cryptoniteEncryptCBC k (cryptoniteMakeIV @Crypto.Cipher.AES.AES128 i)) v
    , bench "openssl" $ nfIO (opensslEncryptCBC c k i v)
    ]
  ]

setupEnv :: Int -> Int -> Int -> IO Env
setupEnv k v i = do
  drg <- Crypto.Random.getSystemDRG
  Just c <- OpenSSL.EVP.Cipher.getCipherByName "AES-128-CBC"
  let (key,iv,input) = genEnv k v i drg
  pure (key, iv, input, c)

genEnv
  :: Crypto.Random.DRG g
  => Int
  -> Int
  -> Int
  -> g
  -> (ByteString, ByteString, ByteString)
genEnv k v i = evalState $ do
  key <- state $ Crypto.Random.randomBytesGenerate k
  iv <- state $ Crypto.Random.randomBytesGenerate v
  input <- state $ Crypto.Random.randomBytesGenerate i
  pure (key, iv, input)

cryptoniteMakeIV :: Crypto.Cipher.Types.BlockCipher c => ByteString -> Crypto.Cipher.Types.IV c
cryptoniteMakeIV = maybe (error "makeIV") id . Crypto.Cipher.Types.makeIV

cryptoniteEncryptCBC
  :: forall c. Crypto.Cipher.Types.BlockCipher c
  => ByteString
  -> Crypto.Cipher.Types.IV c
  -> ByteString
  -> ByteString
cryptoniteEncryptCBC key iv input =
  let
    cipher = Crypto.Error.throwCryptoError @c
      (Crypto.Cipher.Types.cipherInit key)
  in Crypto.Cipher.Types.cbcEncrypt cipher iv input

opensslEncryptCBC
  :: OpenSSL.EVP.Cipher.Cipher
  -> ByteString
  -> ByteString
  -> ByteString
  -> IO ByteString
opensslEncryptCBC c key iv input = do
  OpenSSL.EVP.Cipher.cipherBS c key iv OpenSSL.EVP.Cipher.Encrypt input


instance NFData (Crypto.Cipher.Types.IV c) where rnf = rwhnf
instance NFData OpenSSL.EVP.Cipher.Cipher where rnf = rwhnf
