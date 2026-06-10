from setuptools import find_packages, setup


setup(
    name="mcp-tool-risk-audit",
    version="0.1.1",
    description="Audit MCP tool configs and manifests for security and operational risk.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="alexzhu0",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages("src"),
    package_data={"mcp_tool_risk_audit": ["rules/default.json"]},
    include_package_data=True,
    python_requires=">=3.9",
    entry_points={"console_scripts": ["mcp-tool-risk-audit=mcp_tool_risk_audit.cli:main"]},
)
