import flexitest

from common.mosaic import get_circuit_path, get_peer_configs
from factories.fdb import generate_fdb_root_directory
from factories.mosaic import MosaicFactoryConfig

DEFAULT_NETWORK_SIZE = 5


class MosaicEnv(flexitest.EnvConfig):
    """Env running mosaic nodes only."""

    network_size: int

    def __init__(self, network_size: int = DEFAULT_NETWORK_SIZE):
        super().__init__()
        self.network_size = network_size

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        # Setup FoundationDB with unique root directory for this environment
        fdb = self.setup_fdb(ectx, "mosaic")
        svcs["fdb"] = fdb

        # Create mosaic config
        mosaic_factory_config = MosaicFactoryConfig(
            circuit_path=get_circuit_path(),
            storage_cluster_file=fdb.props["cluster_file"],
            all_peers=get_peer_configs(self.network_size),
        )

        # Create mosaic instances based on configuration
        for i in range(self.network_size):
            factory = ectx.get_factory("mosaic")
            mosaic_service = factory.create_mosaic_service(ectx.name, i, mosaic_factory_config)

            # register services
            svcs[f"mosaic_{i}"] = mosaic_service

        return flexitest.LiveEnv(svcs)

    def setup_fdb(self, ectx: flexitest.EnvContext, env_name: str):
        """Setup FoundationDB instance with a unique root directory for this environment.

        Args:
            ectx: Environment context
            env_name: Name of this environment (used to generate unique root directory)

        Returns:
            FDB service instance
        """
        fdb_fac = ectx.get_factory("fdb")
        fdb = fdb_fac.create_fdb()

        # Generate unique root directory for this environment
        self.fdb_root_directory_prefix = generate_fdb_root_directory(env_name)

        return fdb


class MosaicTestRuntime(flexitest.TestRuntime):
    """
    Extended testenv. StrataTestRuntime to call custom run context
    """

    def create_run_context(self, name: str, env: flexitest.LiveEnv) -> flexitest.RunContext:
        return MosaicRunContext(self.datadir_root, name, env)


class MosaicRunContext(flexitest.RunContext):
    """
    Custom run context which provides access to services and some test specific variables.
    """

    def __init__(self, datadir_root: str, name: str, env: flexitest.LiveEnv):
        super().__init__(env)
        self.name = name
        self.datadir_root = datadir_root
