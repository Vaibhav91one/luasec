<html>
<body>
<% local h = http.formvalue("h") %>
<% os.execute("ping " .. h) %>
</body>
</html>
