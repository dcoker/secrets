# Notice!

Secrets has been replaced by https://github.com/dcoker/biscuit.  

If you are a current user of Secrets, know that Biscuit provides the same functionality and more, including multi-region support. Your existing .yml files can be migrated simply by converting the values of the YAML dictionaries into a list instead of scalars. 

For example, change this:

```
password:
  key_id: ...
  key_ciphertext: ...
```

to:

```
password:
- key_id: ...
  key_ciphertext: ...
```
