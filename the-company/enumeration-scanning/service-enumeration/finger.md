# Finger

nmap -sV -sC 10.10.10.4 -p 79

### **Banner Grabbing/Basic connection**

```
nc -vn <IP> 79
echo "root" | nc -vn <IP> 79
```

### Find Logged in users on target.

```
finger @10.10.10.4
```

### Check User is existed or not.

```
finger USERNAME@<ip>
```
