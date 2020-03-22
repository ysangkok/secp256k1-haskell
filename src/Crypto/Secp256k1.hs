{-# LANGUAGE CPP                   #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GADTs #-}
{-|
Module      : Crypto.Secp256k1
License     : MIT
Maintainer  : Jean-Pierre Rupp <root@haskoin.com>
Stability   : experimental
Portability : POSIX

Crytpographic functions from Bitcoin’s secp256k1 library.
-}
module Crypto.Secp256k1
    ( -- * Messages
    Msg
    , msg
    , getMsg

    -- * Secret Keys
    , SecKey
    , secKey
    , getSecKey
    , derivePubKey

    -- * Public Keys
    , PubKey
    , importPubKey
    , exportPubKey

    -- * Signatures
    , Sig
    , signMsg
    , verifySig
    , normalizeSig
    -- ** DER
    , importSig
    , exportSig
    -- Schnorr
    , signMsgSchnorr
    , exportSchnorrSig
    , importSchnorrSig
    , exportXOnlyPubKey
    , importXOnlyPubKey
    , verifyMsgSchnorr
    , createXOnlyPubKey
    , schnorrTweakAddPubKey
    , schnorrTweakAddSecKey
    , testTweakXOnlyPubKey
    , SchnorrSig
    , XOnlyPubKey
    -- ** Compact
    , CompactSig(..)
    , exportCompactSig
    , importCompactSig
    -- * Recoverable
    , RecSig
    , CompactRecSig(..)
    , importCompactRecSig
    , exportCompactRecSig
    , convertRecSig
    , signRecMsg
    , recover

    -- * Addition & Multiplication
    , Tweak
    , tweak
    , getTweak
    , tweakAddSecKey
    , tweakMulSecKey
    , tweakAddPubKey
    , tweakMulPubKey
    , combinePubKeys
    , tweakNegate

#ifdef ECDH
    -- * Diffie Hellman
    , ecdh
#endif
    , wMusigPubKeyCombine
    , wMusigSetNonce
    , wMusigCombineNonces
    , wMusigGetPublicNonce
    , wMusigPartialSignatureSerialize
    , wMusigPartialSignatureParse
    , wMusigSessionInit
    , wMusigPartialSign
    , wMusigPartialSignatureCombine
    , wMusigPartialSignatureAdapt
    , wMusigExtractSecKey
    , nonceCommitment
    , NonceCommitment
    , getNonceCommitment
    , SessionId
    , sessionId
    , getSessionId
    , WPartialSignature
    , WMusigPreSession
    , WMusigSession
    , WMusigRound2
    , WSignerData
    , PublicNonce
    ) where

import           Control.Monad             (replicateM, unless, (<=<), guard)
import           Control.Monad.IO.Class    (liftIO)
import           Control.Monad.Trans.Maybe (runMaybeT)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as B16
import           Data.ByteString.Short     (fromShort, toShort)
import           Data.Hashable             (Hashable (..))
import           Data.Vector.Fixed         (Vector, Dim, toList, length)
import           Data.Maybe                (fromJust, fromMaybe, isJust)
import           Data.Serialize            (decode, encode)
import           Data.String               (IsString (..))
import           Data.String.Conversions   (ConvertibleStrings, cs)
import           Foreign                   (ForeignPtr, alloca, allocaArray,
                                            allocaBytes, mallocForeignPtr,
                                            nullFunPtr, nullPtr, peek, poke,
                                            pokeArray, withForeignPtr,
                                            advancePtr, Ptr, withArray,
                                            mallocForeignPtrArray,
                                            withArrayLen)
import           Foreign.C                 (CInt, CSize)
import           System.IO.Unsafe          (unsafePerformIO)
import           Test.QuickCheck           (Arbitrary (..),
                                            arbitraryBoundedRandom, suchThat)
import           Text.Read                 (Lexeme (String), lexP, parens,
                                            pfail, readPrec)

import           Control.DeepSeq
import           Crypto.Secp256k1.Internal
import           GHC.TypeLits              (KnownNat)
import           GHC.TypeLits.Witnesses    (SNat, fromSNat)
import           GHC.Natural               (naturalToInt, naturalToInteger)
import           Prelude hiding            (length)
import qualified Prelude

singToSize :: SNat n -> CSize
singToSize = fromInteger . naturalToInteger . fromSNat

newtype PubKey = PubKey (ForeignPtr PubKey64)
newtype XOnlyPubKey = XOnlyPubKey (ForeignPtr PubKey64)
newtype Msg = Msg (ForeignPtr Msg32)
newtype Sig = Sig (ForeignPtr Sig64)
newtype SchnorrSig = SchnorrSig (ForeignPtr Sig64)
newtype SecKey = SecKey (ForeignPtr SecKey32)
newtype Tweak = Tweak (ForeignPtr Tweak32)
newtype RecSig = RecSig (ForeignPtr RecSig65)
data WMusigPreSession n where
    WMusigPreSession :: KnownNat n => ForeignPtr MusigPreSession -> WMusigPreSession n
data WMusigSession n where
    WMusigSession :: KnownNat n => ForeignPtr MusigSession -> WMusigSession n
data WMusigRound2 n where
    WMusigRound2 :: KnownNat n => ForeignPtr MusigSession -> WMusigRound2 n
newtype WPartialSignature = WPartialSignature (ForeignPtr PartialSignature)
data WSignerData n where
    WSignerData :: KnownNat n => ForeignPtr MusigSignerData -> WSignerData n
newtype NonceCommitment = NonceCommitment (ForeignPtr NonceCommitment32)
newtype SessionId = SessionId (ForeignPtr SessionId32)
newtype PublicNonce = PublicNonce (ForeignPtr PublicNonce32)

instance NFData PubKey where
    rnf (PubKey p) = p `seq` ()

instance NFData Msg where
    rnf (Msg p) = p `seq` ()

instance NFData Sig where
    rnf (Sig p) = p `seq` ()

instance NFData SecKey where
    rnf (SecKey p) = p `seq` ()

instance NFData Tweak where
    rnf (Tweak p) = p `seq` ()

instance NFData RecSig where
    rnf (RecSig p) = p `seq` ()

decodeHex :: ConvertibleStrings a ByteString => a -> Maybe ByteString
decodeHex str = if BS.null r then Just bs else Nothing where
    (bs, r) = B16.decode $ cs str

instance Read PubKey where
    readPrec = do
        String str <- lexP
        maybe pfail return $ importPubKey =<< decodeHex str

instance Hashable PubKey where
    i `hashWithSalt` k = i `hashWithSalt` exportPubKey True k

instance IsString PubKey where
    fromString = fromMaybe e . (importPubKey <=< decodeHex) where
        e = error "Could not decode public key from hex string"

instance Show PubKey where
    showsPrec _ = shows . B16.encode . exportPubKey True

instance Read XOnlyPubKey where
    readPrec = do
        String str <- lexP
        maybe pfail return $ importXOnlyPubKey =<< decodeHex str

instance Hashable XOnlyPubKey where
    i `hashWithSalt` k = i `hashWithSalt` exportXOnlyPubKey k

instance IsString XOnlyPubKey where
    fromString = fromMaybe e . (importXOnlyPubKey <=< decodeHex) where
        e = error "Could not decode public key from hex string"

instance Show XOnlyPubKey where
    showsPrec _ = shows . B16.encode . exportXOnlyPubKey

instance Read Msg where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ msg =<< decodeHex str

instance Hashable Msg where
    i `hashWithSalt` m = i `hashWithSalt` getMsg m

instance IsString Msg where
    fromString = fromMaybe e . (msg <=< decodeHex)  where
        e = error "Could not decode message from hex string"

instance Show Msg where
    showsPrec _ = shows . B16.encode . getMsg

instance Read Sig where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ importSig =<< decodeHex str

instance IsString Sig where
    fromString = fromMaybe e . (importSig <=< decodeHex) where
        e = error "Could not decode signature from hex string"

instance Hashable Sig where
    i `hashWithSalt` s = i `hashWithSalt` exportSig s

instance Show Sig where
    showsPrec _ = shows . B16.encode . exportSig

recSigFromString :: String -> Maybe RecSig
recSigFromString str = do
    bs <- decodeHex str
    rs <- either (const Nothing) Just $ decode bs
    importCompactRecSig rs

instance Hashable RecSig where
    i `hashWithSalt` s = i `hashWithSalt` encode (exportCompactRecSig s)

instance Read RecSig where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ recSigFromString str

instance IsString RecSig where
    fromString = fromMaybe e . recSigFromString
      where
        e = error "Could not decode signature from hex string"

instance Show RecSig where
    showsPrec _ = shows . B16.encode . encode . exportCompactRecSig

instance Read SecKey where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ secKey =<< decodeHex str

instance Hashable SecKey where
    i `hashWithSalt` k = i `hashWithSalt` getSecKey k

instance IsString SecKey where
    fromString = fromMaybe e . (secKey <=< decodeHex) where
        e = error "Colud not decode secret key from hex string"

instance Show SecKey where
    showsPrec _ = shows . B16.encode . getSecKey

instance Hashable Tweak where
    i `hashWithSalt` t = i `hashWithSalt` getTweak t

instance Read Tweak where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ tweak =<< decodeHex str

instance IsString Tweak where
    fromString = fromMaybe e . (tweak <=< decodeHex) where
        e = error "Could not decode tweak from hex string"

instance Show Tweak where
    showsPrec _ = shows . B16.encode . getTweak

instance Eq PubKey where
    fp1 == fp2 = getPubKey fp1 == getPubKey fp2

instance Eq XOnlyPubKey where
    fp1 == fp2 = getXOnlyPubKey fp1 == getXOnlyPubKey fp2

instance Eq Msg where
    fm1 == fm2 = getMsg fm1 == getMsg fm2

instance Eq Sig where
    fg1 == fg2 = exportCompactSig fg1 == exportCompactSig fg2

instance Eq RecSig where
    fg1 == fg2 = exportCompactRecSig fg1 == exportCompactRecSig fg2

instance Eq SecKey where
    fk1 == fk2 = getSecKey fk1 == getSecKey fk2

instance Eq Tweak where
    ft1 == ft2 = getTweak ft1 == getTweak ft2

-- | Import 32-byte 'ByteString' as 'Msg'.
msg :: ByteString -> Maybe Msg
msg bs
    | BS.length bs == 32 = unsafePerformIO $ do
        fp <- mallocForeignPtr
        withForeignPtr fp $ flip poke (Msg32 (toShort bs))
        return $ Just $ Msg fp
    | otherwise = Nothing

-- | Import 32-byte 'ByteString' as 'SecKey'.
secKey :: ByteString -> Maybe SecKey
secKey bs
    | BS.length bs == 32 = withContext $ \ctx -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \p -> do
            poke p (SecKey32 (toShort bs))
            ecSecKeyVerify ctx p
        if isSuccess ret
            then return $ Just $ SecKey fp
            else return Nothing
    | otherwise = Nothing

-- | Convert signature to a normalized lower-S form. Boolean value 'True'
-- indicates that the signature changed, 'False' indicates that it was already
-- normal.
normalizeSig :: Sig -> (Sig, Bool)
normalizeSig (Sig fg) = withContext $ \ctx -> do
    fg' <- mallocForeignPtr
    ret <- withForeignPtr fg $ \pg -> withForeignPtr fg' $ \pg' ->
        ecdsaSignatureNormalize ctx pg' pg
    return (Sig fg', isSuccess ret)

-- | 32-Byte 'ByteString' as 'Tweak'.
tweak :: ByteString -> Maybe Tweak
tweak bs
    | BS.length bs == 32 = unsafePerformIO $ do
        fp <- mallocForeignPtr
        withForeignPtr fp $ flip poke (Tweak32 (toShort bs))
        return $ Just $ Tweak fp
    | otherwise = Nothing

-- | Get 32-byte secret key.
getSecKey :: SecKey -> ByteString
getSecKey (SecKey fk) =
    fromShort $ getSecKey32 $ unsafePerformIO $ withForeignPtr fk peek

-- Get 64-byte public key.
getXOnlyPubKey :: XOnlyPubKey -> ByteString
getXOnlyPubKey (XOnlyPubKey fp) =
    fromShort $ getPubKey64 $ unsafePerformIO $ withForeignPtr fp peek

-- Get 64-byte public key.
getPubKey :: PubKey -> ByteString
getPubKey (PubKey fp) =
    fromShort $ getPubKey64 $ unsafePerformIO $ withForeignPtr fp peek

-- | Get 32-byte message.
getMsg :: Msg -> ByteString
getMsg (Msg fm) =
    fromShort $ getMsg32 $ unsafePerformIO $ withForeignPtr fm peek

-- | Get 32-byte tweak.
getTweak :: Tweak -> ByteString
getTweak (Tweak ft) =
    fromShort $ getTweak32 $ unsafePerformIO $ withForeignPtr ft peek

-- | Get 32-byte nonce commitment.
getNonceCommitment :: NonceCommitment -> ByteString
getNonceCommitment (NonceCommitment ft) =
    fromShort $ getNonceCommitment32 $ unsafePerformIO $ withForeignPtr ft peek

-- | Get 32-byte session id.
getSessionId :: SessionId -> ByteString
getSessionId (SessionId ft) =
    fromShort $ getSessionId32 $ unsafePerformIO $ withForeignPtr ft peek

-- | Import DER-encoded public key.
importPubKey :: ByteString -> Maybe PubKey
importPubKey bs =  withContext $ \ctx -> useByteString bs $ \(b, l) -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> ecPubKeyParse ctx p b l
    if isSuccess ret then return $ Just $ PubKey fp else return Nothing

-- | Encode public key as DER. First argument 'True' for compressed output.
exportPubKey :: Bool -> PubKey -> ByteString
exportPubKey compress (PubKey pub) = withContext $ \ctx ->
    withForeignPtr pub $ \p -> alloca $ \l -> allocaBytes z $ \o -> do
        poke l (fromIntegral z)
        ret <- ecPubKeySerialize ctx o l p c
        unless (isSuccess ret) $ error "could not serialize public key"
        n <- peek l
        packByteString (o, n)
  where
    c = if compress then compressed else uncompressed
    z = if compress then 33 else 65

exportCompactSig :: Sig -> CompactSig
exportCompactSig (Sig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \pg -> alloca $ \pc -> do
        ret <- ecdsaSignatureSerializeCompact ctx pc pg
        unless (isSuccess ret) $ error "Could not obtain compact signature"
        peek pc

importCompactSig :: CompactSig -> Maybe Sig
importCompactSig c = withContext $ \ctx -> alloca $ \pc -> do
    poke pc c
    fg <- mallocForeignPtr
    ret <- withForeignPtr fg $ \pg -> ecdsaSignatureParseCompact ctx pg pc
    if isSuccess ret then return $ Just $ Sig fg else return Nothing

-- | Import DER-encoded signature.
importSig :: ByteString -> Maybe Sig
importSig bs = withContext $ \ctx ->
    useByteString bs $ \(b, l) -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g -> ecdsaSignatureParseDer ctx g b l
        if isSuccess ret then return $ Just $ Sig fg else return Nothing

exportSchnorrSig :: SchnorrSig -> ByteString
exportSchnorrSig (SchnorrSig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \g -> allocaBytes 64 $ \o -> do
        ret <- signatureSerializeSchnorr ctx o g
        unless (isSuccess ret) $ error "could not serialize signature"
        packByteString (o, 64)

importXOnlyPubKey :: ByteString -> Maybe XOnlyPubKey
importXOnlyPubKey bs
    | BS.length bs == 32 = withContext $ \ctx -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \pfp -> useByteString bs $ \(inp, _) ->
            schnorrXOnlyPubKeyImport ctx pfp inp
        if isSuccess ret
            then return $ Just $ XOnlyPubKey fp
            else return Nothing
    | otherwise = Nothing

importSchnorrSig :: ByteString -> Maybe SchnorrSig
importSchnorrSig bs
    | BS.length bs == 64 = withContext $ \ctx -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \pfp -> useByteString bs $ \(inp, _) ->
            schnorrSigImport ctx pfp inp
        if isSuccess ret
            then return $ Just $ SchnorrSig fp
            else return Nothing
    | otherwise = Nothing

verifyMsgSchnorr :: XOnlyPubKey -> SchnorrSig -> Msg -> Bool
verifyMsgSchnorr (XOnlyPubKey fp) (SchnorrSig fg) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr fg $ \g ->
        withForeignPtr fm $ \m -> isSuccess <$> schnorrVerify ctx g m p

-- | Encode signature as strict DER.
exportSig :: Sig -> ByteString
exportSig (Sig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \g -> alloca $ \l -> allocaBytes 72 $ \o -> do
        poke l 72
        ret <- ecdsaSignatureSerializeDer ctx o l g
        unless (isSuccess ret) $ error "could not serialize signature"
        n <- peek l
        packByteString (o, n)

-- | Verify message signature. 'True' means that the signature is correct.
verifySig :: PubKey -> Sig -> Msg -> Bool
verifySig (PubKey fp) (Sig fg) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr fg $ \g ->
        withForeignPtr fm $ \m -> isSuccess <$> ecdsaVerify ctx g m p

signMsg :: SecKey -> Msg -> Sig
signMsg (SecKey fk) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr fm $ \m -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g -> ecdsaSign ctx g m k nullFunPtr nullPtr
        unless (isSuccess ret) $ error "could not sign message"
        return $ Sig fg

signMsgSchnorr :: SecKey -> Msg -> SchnorrSig
signMsgSchnorr (SecKey fk) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr fm $ \m -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g -> schnorrSign ctx g m k nullFunPtr nullPtr
        unless (isSuccess ret) $ error "could not sign message"
        return $ SchnorrSig fg

derivePubKey :: SecKey -> PubKey
derivePubKey (SecKey fk) = withContext $ \ctx -> withForeignPtr fk $ \k -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> ecPubKeyCreate ctx p k
    unless (isSuccess ret) $ error "could not compute public key"
    return $ PubKey fp

exportXOnlyPubKey :: XOnlyPubKey -> ByteString
exportXOnlyPubKey (XOnlyPubKey pub) = withContext $ \ctx ->
    withForeignPtr pub $ \p -> allocaBytes 32 $ \o -> do
        ret <- schnorrPubKeySerialize ctx o p
        unless (isSuccess ret) $ error "could not serialize x-only public key"
        packByteString (o, 32)

createXOnlyPubKey :: SecKey -> XOnlyPubKey
createXOnlyPubKey (SecKey fk) = withContext $ \ctx -> withForeignPtr fk $ \k -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> schnorrXOnlyPubKeyCreate ctx p k
    unless (isSuccess ret) $ error "could not serialize x-only public key"
    return $ XOnlyPubKey fp

-- | Add tweak to secret key.
schnorrTweakAddSecKey :: SecKey -> Tweak -> Maybe SecKey
schnorrTweakAddSecKey (SecKey fk) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr ft $ \t -> do
        fk' <- mallocForeignPtr
        ret <- withForeignPtr fk' $ \k' ->  do
            key <- peek k
            poke k' key
            schnorrSecKeyTweakAdd ctx k' t
        if isSuccess ret then return $ Just $ SecKey fk' else return Nothing

-- | Add tweak to secret key.
tweakAddSecKey :: SecKey -> Tweak -> Maybe SecKey
tweakAddSecKey (SecKey fk) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr ft $ \t -> do
        fk' <- mallocForeignPtr
        ret <- withForeignPtr fk' $ \k' ->  do
            key <- peek k
            poke k' key
            ecSecKeyTweakAdd ctx k' t
        if isSuccess ret then return $ Just $ SecKey fk' else return Nothing

-- | Multiply secret key by tweak.
tweakMulSecKey :: SecKey -> Tweak -> Maybe SecKey
tweakMulSecKey (SecKey fk) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr ft $ \t -> do
        fk' <- mallocForeignPtr
        ret <- withForeignPtr fk' $ \k' ->  do
            key <- peek k
            poke k' key
            ecSecKeyTweakMul ctx k' t
        if isSuccess ret then return $ Just $ SecKey fk' else return Nothing

-- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
tweakAddPubKey :: PubKey -> Tweak -> Maybe PubKey
tweakAddPubKey (PubKey fp) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr ft $ \t -> do
        fp' <- mallocForeignPtr
        ret <- withForeignPtr fp' $ \p' -> do
            pub <- peek p
            poke p' pub
            ecPubKeyTweakAdd ctx p' t
        if isSuccess ret then return $ Just $ PubKey fp' else return Nothing

-- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
schnorrTweakAddPubKey :: XOnlyPubKey -> Tweak -> Maybe (XOnlyPubKey, CInt)
schnorrTweakAddPubKey (XOnlyPubKey fp) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr ft $ \t -> alloca $ \is_negated -> do
        fp' <- mallocForeignPtr
        ret <- withForeignPtr fp' $ \p' -> do
            pub <- peek p
            poke p' pub
            schnorrPubKeyTweakAdd ctx p' is_negated t
        peeked_is_negated <- peek is_negated
        if isSuccess ret then return $ Just $ (XOnlyPubKey fp', peeked_is_negated) else return Nothing

-- | Multiply public key by tweak. Tweak is multiplied first by G to obtain a
-- point.
tweakMulPubKey :: PubKey -> Tweak -> Maybe PubKey
tweakMulPubKey (PubKey fp) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr ft $ \t -> do
        fp' <- mallocForeignPtr
        ret <- withForeignPtr fp' $ \p' ->  do
            pub <- peek p
            poke p' pub
            ecPubKeyTweakMul ctx p' t
        if isSuccess ret then return $ Just $ PubKey fp' else return Nothing

testTweakXOnlyPubKey :: XOnlyPubKey -> CInt -> XOnlyPubKey -> Tweak -> Bool
testTweakXOnlyPubKey (XOnlyPubKey fp) is_negated (XOnlyPubKey internal) (Tweak ft) =
    withContext $ \ctx ->
    withForeignPtr fp $ \p ->
    withForeignPtr internal $ \internalp ->
    withForeignPtr ft $ \t -> do
        ret <- xOnlyPubKeyTweakTest ctx p is_negated internalp t
        return $ isSuccess ret

-- | Add multiple public keys together.
combinePubKeys :: [PubKey] -> Maybe PubKey
combinePubKeys pubs = withContext $ \ctx -> pointers [] pubs $ \ps ->
    allocaArray (Prelude.length ps) $ \a -> do
        pokeArray a ps
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \p ->
            ecPubKeyCombine ctx p a (fromIntegral $ Prelude.length ps)
        if isSuccess ret
            then return $ Just $ PubKey fp
            else return Nothing
  where
    pointers :: [Ptr PubKey64] -> [PubKey] -> ([Ptr PubKey64] -> IO (Maybe PubKey)) -> IO (Maybe PubKey)
    pointers ps [] f = f ps
    pointers ps (PubKey fp : pubs') f =
        withForeignPtr fp $ \p -> pointers (p:ps) pubs' f

-- | Parse a compact ECDSA signature (64 bytes + recovery id).
importCompactRecSig :: CompactRecSig -> Maybe RecSig
importCompactRecSig cr =
  if getCompactRecSigV cr `notElem` [0,1,2,3]
  then Nothing
  else withContext $ \ctx -> alloca $ \pc -> do
    let
      c = CompactSig (getCompactRecSigR cr) (getCompactRecSigS cr)
      recid = fromIntegral $ getCompactRecSigV cr
    poke pc c
    fg <- mallocForeignPtr
    ret <- withForeignPtr fg $ \pg ->
        ecdsaRecoverableSignatureParseCompact ctx pg pc recid
    if isSuccess ret then return $ Just $ RecSig fg else return Nothing

-- | Serialize an ECDSA signature in compact format (64 bytes + recovery id).
exportCompactRecSig :: RecSig -> CompactRecSig
exportCompactRecSig (RecSig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \pg -> alloca $ \pc -> alloca $ \pr -> do
        ret <- ecdsaRecoverableSignatureSerializeCompact ctx pc pr pg
        unless (isSuccess ret) $ error "Could not obtain compact signature"
        CompactSig r s <- peek pc
        v <- fromIntegral <$> peek pr
        return $ CompactRecSig r s v

-- | Convert a recoverable signature into a normal signature.
convertRecSig :: RecSig -> Sig
convertRecSig (RecSig frg) = withContext $ \ctx ->
    withForeignPtr frg $ \prg -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \pg ->
            ecdsaRecoverableSignatureConvert ctx pg prg
        unless (isSuccess ret) $
            error "Could not convert a recoverable signature"
        return $ Sig fg

-- | Create a recoverable ECDSA signature.
signRecMsg :: SecKey -> Msg -> RecSig
signRecMsg (SecKey fk) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr fm $ \m -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g ->
            ecdsaSignRecoverable ctx g m k nullFunPtr nullPtr
        unless (isSuccess ret) $ error "could not sign message"
        return $ RecSig fg

-- | Recover an ECDSA public key from a signature.
recover :: RecSig -> Msg -> Maybe PubKey
recover (RecSig frg) (Msg fm) = withContext $ \ctx ->
    withForeignPtr frg $ \prg -> withForeignPtr fm $ \pm -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \pp -> ecdsaRecover ctx pp prg pm
        if isSuccess ret then return $ Just $ PubKey fp else return Nothing

wMusigSessionInit
    :: KnownNat n => NonceCommitment -> SessionId -> Msg -> XOnlyPubKey
    -> WMusigPreSession n -> CSize -> SecKey -> SNat n
    -> IO (Maybe (WMusigSession n, WSignerData n))
wMusigSessionInit (NonceCommitment fwNonceCommitment)
                  (SessionId fwSessionId) (Msg fwMsg32)
                  (XOnlyPubKey fwCombinedPk)
                  (WMusigPreSession fwMusigPreSession)
                  ourSignerIndex (SecKey fwSecKey) numberOfSigners = runMaybeT $ do
  let nSigners :: CSize = singToSize numberOfSigners
  guard $ ourSignerIndex < nSigners
  --guard $ nSigners /= 0 -- not necessary since previous guard guarantees that nSigners is larger than the minimum ourSignerIndex (CSize), which is 0
  fwMusigSession <- liftIO mallocForeignPtr
  let intNSigners :: Int = naturalToInt $ fromSNat numberOfSigners
  fwSignerData <- liftIO $ mallocForeignPtrArray intNSigners
  ret <-
    liftIO $
      withForeignPtr fctx $ \ctx ->
        withForeignPtr fwMsg32 $ \wMsg32 ->
          withForeignPtr fwCombinedPk $ \wCombinedPk ->
            withForeignPtr fwSecKey $ \wSecKey ->
              withForeignPtr fwMusigPreSession $ \wMusigPreSession ->
                withForeignPtr fwMusigSession $ \wMusigSession ->
                  withForeignPtr fwNonceCommitment $ \wNonceCommitment ->
                    withForeignPtr fwSignerData $ \wSignerData ->
                      withForeignPtr fwSessionId $ \wSessionId ->
                        musigSessionInit
                          ctx
                          wMusigSession    -- output
                          wSignerData      -- output
                          wNonceCommitment -- input, nonce commitment
                          wSessionId -- input, session id
                          wMsg32 -- input, const, optional
                          wCombinedPk -- input, combined pk, const
                          wMusigPreSession -- input, const
                          nSigners -- input, number of signers
                          ourSignerIndex -- input, our signer index in the multi-signature process
                          wSecKey -- input, const
  guard $ isSuccess ret
  return $ (WMusigSession fwMusigSession, WSignerData fwSignerData)

wMusigPubKeyCombine :: (KnownNat n, Vector v XOnlyPubKey, Dim v ~ n) => v XOnlyPubKey -> Maybe (XOnlyPubKey, WMusigPreSession n)
wMusigPubKeyCombine pubKeys = withContext $ \ctx -> runMaybeT $ do
    guard (length pubKeys /= 0)
    let fkList = fmap (\(XOnlyPubKey pk64) -> pk64) (toList pubKeys)
    let copyActions = traverse withForeignPtr fkList peek
    pubKeyList :: [PubKey64] <- liftIO $ sequenceA copyActions
    fcombinedPk <- liftIO mallocForeignPtr
    fpreSession <- liftIO mallocForeignPtr
    ptrScratch <- liftIO $ scratchSpaceCreate ctx (1024 * 1024)
    ret <- liftIO $
        withArray pubKeyList $ \(arrPtr :: Ptr PubKey64) ->
            withForeignPtr fcombinedPk $ \combinedPk ->
                withForeignPtr fpreSession $ \preSession ->
                    musigPubKeyCombine ctx ptrScratch combinedPk preSession arrPtr (intToSize $ length pubKeys)
    liftIO $ scratchSpaceDestroy ctx ptrScratch
    guard $ isSuccess ret
    return (XOnlyPubKey fcombinedPk, WMusigPreSession fpreSession)

wMusigPartialSignatureParse :: ByteString -> Maybe WPartialSignature
wMusigPartialSignatureParse bs = withContext $ \ctx ->
    if BS.length bs /= 32
        then return Nothing
        else do
            fp <- mallocForeignPtr
            ret <-
                useByteString bs $ \(b, l) ->
                    withForeignPtr fp $ \p ->
                        musigPartialSignatureParse ctx p b
            return $
                if isSuccess ret
                    then Just $ WPartialSignature fp
                    else Nothing

wMusigPartialSignatureSerialize :: WPartialSignature -> ByteString
wMusigPartialSignatureSerialize (WPartialSignature fk) = withContext $ \ctx ->
    allocaBytes 32 $ \o -> do
        ret <-
            withForeignPtr fk $ \p ->
                musigPartialSignatureSerialize ctx o p
        unless (isSuccess ret) $ error "could not serialize partial signature"
        packByteString (o, 32)

intToSize :: Int -> CSize
intToSize = fromInteger . toInteger

withPartialSigs :: [WPartialSignature] -> (CSize -> Ptr PartialSignature -> IO a) -> IO a
withPartialSigs partialSigsList bracket =
  let
    fkList = fmap (\(WPartialSignature pk64) -> pk64) partialSigsList
    copyActions = traverse withForeignPtr fkList peek
  in do
    partialSigs <- sequenceA copyActions
    withArrayLen partialSigs $ \x -> bracket $ intToSize x

wMusigPartialSignatureCombine :: (Vector v WPartialSignature, Dim v ~ n) => v WPartialSignature -> WMusigRound2 n -> Maybe SchnorrSig
wMusigPartialSignatureCombine sigList (WMusigRound2 fwMusigSession) = withContext $ \ctx -> do
    sigFPtr <- mallocForeignPtr
    ret <-
        withPartialSigs (toList sigList) $ \len -> \(arrPtr :: Ptr PartialSignature) ->
            withForeignPtr fwMusigSession $ \ptrMusigSession ->
                withForeignPtr sigFPtr $ \sigPtr ->
                    musigPartialSignatureCombine ctx ptrMusigSession sigPtr arrPtr len
    return $
        if isSuccess ret
            then Just (SchnorrSig sigFPtr)
            else Nothing

-- these three are in IO because they modify the session and/or signer data
wMusigGetPublicNonce :: (Vector v NonceCommitment, Dim v ~ n) => WMusigSession n -> WSignerData n -> v NonceCommitment -> IO (Maybe PublicNonce)
wMusigGetPublicNonce (WMusigSession fkSession) (WSignerData fkData) commitments =
  withForeignPtr fctx $ \ctx ->
    let
      fkList :: [ForeignPtr NonceCommitment32]
      fkList = map (\(NonceCommitment pk64) -> pk64) (toList commitments)
      copyActions :: [IO NonceCommitment32]
      copyActions = traverse withForeignPtr fkList peek
      len :: Integer
      len = toInteger $ length commitments
      indexes = [0..((fromInteger len) - 1)]
    in do
      nonceCopyList :: [NonceCommitment32] <- sequenceA copyActions
      fkNonce <- mallocForeignPtr
      ret <-
        withForeignPtr fkNonce $ \ptrNonce ->
          withArray nonceCopyList $ \arrPtr ->
            let
              ptrs :: [Ptr NonceCommitment32]
              ptrs = map (advancePtr arrPtr) indexes
            in
              withArray ptrs $ \(ptrPtr :: Ptr (Ptr NonceCommitment32)) ->
                withForeignPtr fkData $ \ptrData ->
                  withForeignPtr fkSession $ \ptrSession ->
                    musigGetPublicNonce
                      ctx
                      ptrSession
                      ptrData
                      ptrNonce
                      ptrPtr
                      (fromInteger len)
                      nullPtr
      return $
        if isSuccess ret
          then Just (PublicNonce fkNonce)
          else Nothing

-- returns false if nonce not consistent with the one received in get_public_nonce
wMusigSetNonce :: WSignerData n -> PublicNonce -> Int -> IO Bool
wMusigSetNonce (WSignerData fkData) (PublicNonce nonce32) idx =
    withForeignPtr fctx $ \ctx ->
        withForeignPtr fkData $ \ptrData ->
            withForeignPtr nonce32 $ \ptrNonce -> do
                ret <- musigSetNonce ctx (advancePtr ptrData idx) ptrNonce
                return $ isSuccess ret

wMusigCombineNonces :: KnownNat n => WMusigSession n -> WSignerData n -> Maybe XOnlyPubKey -> SNat n -> Maybe (WMusigRound2 n, CInt)
wMusigCombineNonces (WMusigSession fkSess) (WSignerData fkData) maybeAdaptor numberOfSigners =
  withContext $ \ctx -> alloca $ \ptrIsNegated -> do
    -- with linear types we wouldn't need this copy
    sessCopy <- withForeignPtr fkSess peek
    fkNewSess <- mallocForeignPtr
    ret <-
      withForeignPtr fkData $ \ptrData ->
        withForeignPtr fkNewSess $ \ptrSess -> do
          poke ptrSess sessCopy
          let partialApp :: Ptr PubKey64 -> IO Ret =\
            musigCombineNonces ctx ptrSess ptrData (singToSize numberOfSigners) ptrIsNegated
          case maybeAdaptor of
            Nothing ->
              partialApp nullPtr
            Just (XOnlyPubKey fkAdaptor) ->
              withForeignPtr fkAdaptor partialApp
    isNegated <- peek ptrIsNegated
    return $
      if isSuccess ret
        then Just (WMusigRound2 fkNewSess, isNegated)
        else Nothing

wMusigPartialSign :: WMusigRound2 n -> WPartialSignature
wMusigPartialSign (WMusigRound2 fkSess) =
  withContext $ \ctx -> do
    fkPartialSig <- mallocForeignPtr
    ret <-
      withForeignPtr fkPartialSig $ \ptrPartialSig ->
        withForeignPtr fkSess $ \ptrSess ->
          musigPartialSign ctx ptrSess ptrPartialSig
    unless (isSuccess ret) $ error "could not sign to make partial signature"
    return $ WPartialSignature fkPartialSig

wMusigPartialSignatureAdapt :: WPartialSignature -> WPartialSignature -> SecKey -> CInt -> Maybe WPartialSignature
wMusigPartialSignatureAdapt (WPartialSignature fkToAdapt) (WPartialSignature fkAdaptor)
                            (SecKey fkSecKey) isNegated =
  withContext $ \ctx -> do
    adapted <- mallocForeignPtr
    peeked <- withForeignPtr fkToAdapt peek
    ret <-
      withForeignPtr adapted $ \adaptedPtr ->
        withForeignPtr fkSecKey $ \ptrSecKey ->
          withForeignPtr fkAdaptor $ \adaptorPtr -> do
            poke adaptedPtr peeked
            musigSignatureAdapt ctx adaptedPtr adaptorPtr ptrSecKey isNegated
    return $
      if isSuccess ret
        then Just (WPartialSignature adapted)
        else Nothing

wMusigExtractSecKey :: SchnorrSig -> [WPartialSignature] -> CInt -> Maybe SecKey
wMusigExtractSecKey (SchnorrSig fkSig) partialSigs isNegated = withContext $ \ctx -> do
  fkSecKey <- mallocForeignPtr
  ret <-
    withForeignPtr fkSecKey $ \ptrSec ->
      withForeignPtr fkSig $ \ptrSig ->
        withPartialSigs partialSigs $ \len -> \ptrPartialSig ->
          musigExtractSecretAdaptor ctx ptrSec ptrSig ptrPartialSig len isNegated
  return $
    if isSuccess ret
      then Just (SecKey fkSecKey)
      else Nothing

nonceCommitment :: ByteString -> Maybe NonceCommitment
nonceCommitment bs
    | BS.length bs == 32 = unsafePerformIO $ do
        fp <- mallocForeignPtr
        withForeignPtr fp $ flip poke (NonceCommitment32 (toShort bs))
        return $ Just $ NonceCommitment fp
    | otherwise = Nothing

sessionId :: ByteString -> Maybe SessionId
sessionId bs
    | BS.length bs == 32 = unsafePerformIO $ do
        fp <- mallocForeignPtr
        withForeignPtr fp $ flip poke (SessionId32 (toShort bs))
        return $ Just $ SessionId fp
    | otherwise = Nothing

tweakNegate :: Tweak -> Maybe Tweak
tweakNegate (Tweak fk) = withContext $ \ctx -> do
    fnew <- mallocForeignPtr
    peeked <- withForeignPtr fk peek
    ret <- withForeignPtr fnew $ \n -> do
        poke n peeked
        ecTweakNegate ctx n
    return $
        if isSuccess ret
            then Just (Tweak fnew)
            else Nothing

#ifdef ECDH
-- | Compute Diffie-Hellman secret.
ecdh :: PubKey -> SecKey -> ByteString
ecdh (PubKey pk) (SecKey sk) = withContext $ \ctx ->
    withForeignPtr pk $ \pkPtr -> withForeignPtr sk $ \skPtr ->
        allocaBytes size $ \o -> do
            ret <- ecEcdh ctx o pkPtr skPtr nullPtr nullPtr
            unless (isSuccess ret) $ error "ecdh failed"
            packByteString (o, size)
  where
    size :: Integral a => a
    size = 32
#endif

instance Arbitrary Msg where
    arbitrary = gen_msg
      where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = (msg . BS.pack) <$> replicateM 32 arbitraryBoundedRandom
        gen_msg = fromJust <$> valid_bs

instance Arbitrary SecKey where
    arbitrary = gen_key where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = (secKey . BS.pack) <$> replicateM 32 arbitraryBoundedRandom
        gen_key = fromJust <$> valid_bs

instance Arbitrary PubKey where
    arbitrary = do
        key <- arbitrary
        return $ derivePubKey key
