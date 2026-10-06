"""Run the shared TLS/QUIC acceptance campaign for tuic."""
import importlib.util
import pathlib
import sys
spec=importlib.util.spec_from_file_location("quic_interop",pathlib.Path(__file__).with_name("splicore-quic-interop.py"))
campaign=importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)
if __name__=="__main__":
    try:
        campaign.main("tuic")
    except Exception as error:
        print("TUIC INTEROP FAILED: "+type(error).__name__+(": "+str(error) if isinstance(error,RuntimeError) else ""),file=sys.stderr)
        raise SystemExit(1) from None
