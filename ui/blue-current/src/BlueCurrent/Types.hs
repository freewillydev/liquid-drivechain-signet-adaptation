module BlueCurrent.Types where
import System.Exit (ExitCode)
import Data.Text (Text)
data NetworkBinding = NetworkBinding
  { bindingName :: Text, bindingTarget :: Text, bindingReady :: Bool
  , bindingGenesis :: Maybe Text, bindingAsset :: Maybe Text
  , bindingParentGenesis :: Maybe Text, bindingParentForkHeight :: Maybe Integer
  } deriving (Eq,Show)
data Config = Config
  { cfgElementsCli :: FilePath, cfgSimc :: Maybe FilePath, cfgChain :: String
  , cfgDataDir :: Maybe FilePath, cfgRpcPort :: Maybe String, cfgWallet :: String
  , cfgSymphonyBuilder :: Maybe String
  , cfgBinding :: Maybe NetworkBinding
  } deriving (Eq,Show)
data CliResult = CliResult
  { resultExit :: ExitCode, resultStdout :: String, resultStderr :: String
  } deriving (Eq,Show)
