import React from "react";

import pkg from "../../package.json";
const VERSION = pkg.version;

export default function Footer() {
  return (
    <footer style={styles.footer}>
      <span style={styles.version}>v{VERSION}</span>
      <span style={styles.divider}>·</span>
      <span style={styles.credit}>
        Built by{" "}
        <a
          href="https://dnacybersec.com"
          target="_blank"
          rel="noreferrer"
          style={styles.link}
        >
          Rami Hacmon
        </a>
        {" · "}
        <a
          href="https://dnacybersec.com"
          target="_blank"
          rel="noreferrer"
          style={styles.link}
        >
          DNACybersec
        </a>
      </span>
    </footer>
  );
}

const styles = {
  footer: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    padding: "16px 24px",
    borderTop: "1px solid #21262d",
    color: "#4a5568",
    fontSize: 12,
  },
  version: {
    background: "#21262d",
    color: "#6e7681",
    borderRadius: 6,
    padding: "2px 8px",
    fontFamily: "monospace",
    fontSize: 11,
  },
  divider: {
    color: "#30363d",
  },
  credit: {
    color: "#4a5568",
  },
  link: {
    color: "#58a6ff",
    textDecoration: "none",
  },
};
