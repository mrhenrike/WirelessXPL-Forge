            out_path: Destination path for the .tar.gz archive.

        Returns:
            Dict with path, bytes, and head_hash keys.
        """
        if self.simulate:
            logger.info("[EvidenceVault] simulate=True - skipping bundle export")
            return {"path": None, "bytes": 0, "head_hash": _GENESIS, "simulated": True}

        out = Path(out_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        with tarfile.open(str(out), "w:gz") as tar:
            if self._db_path and self._db_path.exists():
                tar.add(str(self._db_path), arcname=self._db_path.name)
            if self._artifacts_dir and self._artifacts_dir.exists():
                for art in self._artifacts_dir.glob("artifact_*.bin"):
                    tar.add(str(art), arcname=art.name)

        return {
            "path": str(out),
            "bytes": out.stat().st_size,
            "head_hash": self._last_hash,
        }

    def export_csv(self, out_path: str | Path, table: str = "networks") -> str:
        """Export a table to CSV.

        Args:
            out_path: Output CSV file path.
            table: One of 'networks', 'captures', 'credentials'.

        Returns:
            Absolute path to the written file.
        """
        allowed = {"networks", "captures", "credentials"}
        if table not in allowed:
            raise ValueError(f"table must be one of {sorted(allowed)}")

        out = Path(out_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if self.simulate:
            logger.info("[EvidenceVault] simulate=True - skipping CSV export")
            return str(out)

        with self._conn() as conn:
            rows = [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]

        if rows:
            with open(str(out), "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

        return str(out)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def head_hash(self) -> str:
        """Current chain head hash."""
        return self._last_hash

    def summary(self) -> dict[str, Any]:
        """Return a lightweight summary of vault contents."""
        if self.simulate:
            return {"session": self.session_id, "simulated": True}
        with self._conn() as conn:
            return {
                "session": self.session_id,
                "operator": self.operator,
                "networks": conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0],
                "captures": conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0],
                "credentials": conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0],
                "ledger_entries": conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0],
                "head_hash": self._last_hash,
            }
