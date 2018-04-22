{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Main (main) where

import           Control.DeepSeq
import           Control.Monad.State.Strict
import           Criterion.Main
import           Criterion.Types
import qualified Crypto.Cipher.AES
import qualified Crypto.Cipher.Blowfish
import qualified Crypto.Cipher.Twofish
import qualified Crypto.Cipher.Types
import qualified Crypto.Error
import qualified Crypto.Random
import           Data.ByteString (ByteString)
import qualified OpenSSL.EVP.Cipher


type Env = (ByteString, ByteString, ByteString)

newtype E p a = E (ByteString, ByteString, ByteString)

-- packages
data Cryptonite
data HsOpenSSL

-- ciphers
data AES_128_CBC
data AES_256_CBC
data Blowfish_128_CBC
data Twofish_128_CBC

-- | Prepare environment for a cipher benchmark
class CipherEnv p a where
  type Input p a

  buildEnv :: E p a -> IO (Input p a)

instance CipherEnv Cryptonite AES_128_CBC where
  type Input Cryptonite AES_128_CBC =
    (ByteString, Crypto.Cipher.Types.IV Crypto.Cipher.AES.AES128)

  buildEnv (E (key, iv, _)) = do
    let Just iv' = Crypto.Cipher.Types.makeIV iv
    pure (key, iv')

instance CipherEnv Cryptonite AES_256_CBC where
  type Input Cryptonite AES_256_CBC =
    (ByteString, Crypto.Cipher.Types.IV Crypto.Cipher.AES.AES256)

  buildEnv (E (key, iv, _)) = do
    let Just iv' = Crypto.Cipher.Types.makeIV iv
    pure (key, iv')

instance CipherEnv Cryptonite Blowfish_128_CBC where
  type Input Cryptonite Blowfish_128_CBC =
    (ByteString, Crypto.Cipher.Types.IV Crypto.Cipher.Blowfish.Blowfish128)

  buildEnv (E (key, iv, _)) = do
    let Just iv' = Crypto.Cipher.Types.makeIV iv
    pure (key, iv')

instance CipherEnv Cryptonite Twofish_128_CBC where
  type Input Cryptonite Twofish_128_CBC =
    (ByteString, Crypto.Cipher.Types.IV Crypto.Cipher.Twofish.Twofish128)

  buildEnv (E (key, iv, _)) = do
    let Just iv' = Crypto.Cipher.Types.makeIV iv
    pure (key, iv')

instance CipherEnv HsOpenSSL AES_128_CBC where
  type Input HsOpenSSL AES_128_CBC =
    (ByteString, ByteString, OpenSSL.EVP.Cipher.Cipher)

  buildEnv (E (key, iv, _)) = do
    Just c <- OpenSSL.EVP.Cipher.getCipherByName "AES-128-CBC"
    pure (key, iv, c)

instance CipherEnv HsOpenSSL AES_256_CBC where
  type Input HsOpenSSL AES_256_CBC =
    (ByteString, ByteString, OpenSSL.EVP.Cipher.Cipher)

  buildEnv (E (key, iv, _)) = do
    Just c <- OpenSSL.EVP.Cipher.getCipherByName "AES-256-CBC"
    pure (key, iv, c)

instance CipherEnv HsOpenSSL Blowfish_128_CBC where
  type Input HsOpenSSL Blowfish_128_CBC =
    (ByteString, ByteString, OpenSSL.EVP.Cipher.Cipher)

  buildEnv (E (key, iv, _)) = do
    Just c <- OpenSSL.EVP.Cipher.getCipherByName "BF-CBC"
    pure (key, iv, c)

main :: IO ()
main = defaultMainWith
  defaultConfig { csvFile = Just "out.csv" }
  [ bgroup "encrypt" cipherEncryptBench
  ]

setupEnv :: Int -> Int -> Int -> IO Env
setupEnv k v i = genEnv k v i <$> Crypto.Random.getSystemDRG

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

cipherEncryptBench :: [Benchmark]
cipherEncryptBench =
  [ env (setupEnv 16 16 1024) $ \ ~(k,i,v) -> bgroup "AES-128-CBC"
    [ env (buildEnv $ E @Cryptonite @AES_128_CBC (k,i,v)) $ \ ~(key,iv) ->
        bench "cryptonite" $ nf (encryptCryptoniteCBC key iv) v
    , env (buildEnv $ E @HsOpenSSL  @AES_128_CBC (k,i,v)) $ \ ~(key,iv,c) ->
        bench "HsOpenSSL" $ nfIO (encryptHsOpenSSLCBC c key iv v)
    ]
  , env (setupEnv 32 16 1024) $ \ ~(k,i,v) -> bgroup "AES-256-CBC"
    [ env (buildEnv $ E @Cryptonite @AES_256_CBC (k,i,v)) $ \ ~(key,iv) ->
        bench "cryptonite" $ nf (encryptCryptoniteCBC key iv) v
    , env (buildEnv $ E @HsOpenSSL  @AES_256_CBC (k,i,v)) $ \ ~(key,iv,c) ->
        bench "HsOpenSSL" $ nfIO (encryptHsOpenSSLCBC c key iv v)
    ]
  , env (setupEnv 16 8 1024) $ \ ~(k,i,v) -> bgroup "Blowfish-128-CBC"
    [ env (buildEnv $ E @Cryptonite @Blowfish_128_CBC (k,i,v)) $ \ ~(key,iv) ->
        bench "cryptonite" $ nf (encryptCryptoniteCBC key iv) v
    , env (buildEnv $ E @HsOpenSSL  @Blowfish_128_CBC (k,i,v)) $ \ ~(key,iv,c) ->
        bench "HsOpenSSL" $ nfIO (encryptHsOpenSSLCBC c key iv v)
    ]
  , env (setupEnv 16 16 1024) $ \ ~(k,i,v) -> bgroup "Twofish-128-CBC"
    [ env (buildEnv $ E @Cryptonite @Twofish_128_CBC (k,i,v)) $ \ ~(key,iv) ->
        bench "cryptonite" $ nf (encryptCryptoniteCBC key iv) v
    ]
  ]

encryptCryptoniteCBC
  :: forall c. Crypto.Cipher.Types.BlockCipher c
  => ByteString
  -> Crypto.Cipher.Types.IV c
  -> ByteString
  -> ByteString
encryptCryptoniteCBC key = Crypto.Cipher.Types.cbcEncrypt cipher
  where
    cipher = Crypto.Error.throwCryptoError @c (Crypto.Cipher.Types.cipherInit key)

encryptHsOpenSSLCBC
  :: OpenSSL.EVP.Cipher.Cipher
  -> ByteString
  -> ByteString
  -> ByteString
  -> IO ByteString
encryptHsOpenSSLCBC c key iv =
  OpenSSL.EVP.Cipher.cipherBS c key iv OpenSSL.EVP.Cipher.Encrypt


instance NFData (Crypto.Cipher.Types.IV c) where rnf = rwhnf
instance NFData OpenSSL.EVP.Cipher.Cipher where rnf = rwhnf
