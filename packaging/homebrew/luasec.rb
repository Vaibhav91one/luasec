class Luasec < Formula
  desc "Static security scanner for Lua in embedded firmware: finds remote code execution"
  homepage "https://github.com/Vaibhav91one/luasec"
  url "https://github.com/Vaibhav91one/luasec/releases/download/v@VERSION@/luasec-@VERSION@.tar.gz"
  sha256 "@SHA256@"
  license "MIT"

  depends_on "lua"

  def install
    libexec.install Dir["*"]
    (bin/"luasec").write_env_script libexec/"bin/luasec", LUA: Formula["lua"].opt_bin/"lua"
  end

  test do
    assert_match "luasec #{version}", shell_output("#{bin}/luasec --version")
    (testpath/"t.lua").write "os.execute(io.read())\n"
    assert_match "[709] critical", shell_output("#{bin}/luasec #{testpath}/t.lua", 1)
  end
end
