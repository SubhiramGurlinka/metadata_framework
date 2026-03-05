# state_manager/orchestrator.py

import json
import subprocess
from typing import Dict, Any, List

from state_manager.manager import StateManager


class FrameworkExecutionError(Exception):
    pass

class FrameworkOrchestrator:
    def __init__(
        self,
        state_manager: StateManager,
        framework_path: str = "main.py",
        python_exec: str = "python",
        timeout: int = 60,
    ):
        self.state_manager = state_manager
        self.framework_path = framework_path
        self.python_exec = python_exec
        self.timeout = timeout

    # ==========================================
    # Run for ALL stored vendor/product/base/fix
    # ==========================================

    def run_all(self) -> List[Dict[str, Any]]:

        state = self.state_manager._load_state()
        results = []

        for vendor, products in state.items():
            for product, base_versions in products.items():
                for base_version, fix_versions in base_versions.items():

                    for fix_version in fix_versions.keys():

                        framework_output = self._execute_framework(
                            vendor=vendor,
                            product=product,
                            base_version=base_version,
                            fix_version=fix_version,
                        )

                        diff = self.state_manager.process(framework_output)

                        results.append(
                            {
                                "vendor": vendor,
                                "product": product,
                                "base_version": base_version,
                                "fix_version": fix_version,
                                "diff": diff,
                            }
                        )

        return results

    # ==========================================
    # Framework Execution
    # ==========================================
    def _execute_framework(
            self,
            vendor: str,
            product: str,
            base_version: str,
            fix_version: str,
        ) -> Dict[str, Any]:

        cmd = [
            self.python_exec,
            self.framework_path,
            "--vendor",
            vendor,
            "--product",
            product,
            "--base-version",
            base_version,
            "--fix-version",
            fix_version,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )

        if result.returncode != 0:
            raise FrameworkExecutionError(
                f"""
                Framework execution failed
                Command: {' '.join(cmd)}
                Return code: {result.returncode}
                STDOUT:
                {result.stdout}

                STDERR:
                {result.stderr}
                """.strip()
                        )

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise FrameworkExecutionError(
                f"""
                Framework returned invalid JSON
                STDOUT:
                {result.stdout}
                STDERR:
                {result.stderr}
                """.strip()
                        ) from e

    # def _execute_framework(
    #     self,
    #     vendor: str,
    #     product: str,
    #     base_version: str,
    #     fix_version: str,
    # ) -> Dict[str, Any]:

    #     cmd = [
    #         self.python_exec,
    #         self.framework_path,
    #         "--vendor",
    #         vendor,
    #         "--product",
    #         product,
    #         "--base-version",
    #         base_version,
    #         "--fix-version",
    #         fix_version,
    #     ]

    #     try:
    #         result = subprocess.run(
    #             cmd,
    #             capture_output=True,
    #             text=True,
    #             timeout=self.timeout,
    #             check=True,
    #         )
    #     except subprocess.TimeoutExpired as e:
    #         raise FrameworkExecutionError(
    #             f"Framework timeout for {vendor}/{product}/{base_version}/{fix_version}"
    #         ) from e
    #     except subprocess.CalledProcessError as e:
    #         raise FrameworkExecutionError(
    #             f"Framework failed: {e.stderr}"
    #         ) from e

    #     try:
    #         return json.loads(result.stdout)
    #     except json.JSONDecodeError as e:
    #         raise FrameworkExecutionError(
    #             "Framework returned invalid JSON"
    #         ) from e
        
# ==========================================
# CLI ENTRYPOINT
# ==========================================

import argparse
import logging
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Run framework checks for all stored vendor/product/base/fix combinations."
    )

    parser.add_argument(
        "--state-file",
        default="pre_state.json",
        help="Path to state file (default: pre_state.json)",
    )

    parser.add_argument(
        "--framework-path",
        default="main.py",
        help="Path to framework script",
    )

    parser.add_argument(
        "--python-exec",
        default=sys.executable,
        help="Python interpreter to use",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    manager = StateManager(args.state_file)
    orchestrator = FrameworkOrchestrator(
        state_manager=manager,
        framework_path=args.framework_path,
        python_exec=args.python_exec,
    )

    try:
        results = orchestrator.run_all()
    except Exception as e:
        logging.exception("Execution failed")
        sys.exit(1)

    total_changes = 0

    for result in results:
        diff = result["diff"]
        if diff["is_new"] or diff["changes"]:
            total_changes += 1
            logging.warning(
                "Change detected: %s/%s/%s/%s -> %s",
                result["vendor"],
                result["product"],
                result["base_version"],
                result["fix_version"],
                diff,
            )

    if total_changes == 0:
        logging.info("No changes detected.")

    logging.info("Completed. Total checked: %d", len(results))


if __name__ == "__main__":
    main()