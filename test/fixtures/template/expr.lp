<html>
<body>
<% local h = http.formvalue("h") %>
<p><%= os.execute("ping " .. h) %></p>
</body>
</html>
