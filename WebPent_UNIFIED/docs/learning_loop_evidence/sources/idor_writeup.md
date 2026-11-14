# IDOR writeup source
Source: https://portswigger.net/web-security/access-control/idor

Insecure direct object references arise when an application uses user-supplied input to access objects directly. A customer page may use `/customer_account?customer_number=132355`; modifying the identifier can expose another customer's record when authorization is missing. Static files such as `/static/12144.txt` can have the same pattern. Test route and parameter ownership with controlled identifiers and a negative control.
