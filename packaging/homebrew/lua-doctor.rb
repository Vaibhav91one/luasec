class LuaDoctor < Formula
  desc "Static security scanner for Lua in embedded firmware: finds remote code execution"
  homepage "https://github.com/doctor-labs/lua-doctor"
  url "https://github.com/doctor-labs/lua-doctor/releases/download/v@VERSION@/lua-doctor-@VERSION@.tar.gz"
  sha256 "@SHA256@"
  license "MIT"

  depends_on "lua"

  def install
    libexec.install Dir["*"]
    (bin/"lua-doctor").write_env_script libexec/"bin/lua-doctor", LUA: Formula["lua"].opt_bin/"lua"
  end

  test do
    assert_match "lua-doctor #{version}", shell_output("#{bin}/lua-doctor --version")
    (testpath/"t.lua").write "os.execute(io.read())\n"
    assert_match "[709] critical", shell_output("#{bin}/lua-doctor #{testpath}/t.lua", 1)
  end
end
