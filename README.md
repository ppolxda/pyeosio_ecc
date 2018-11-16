# pyeosio_ecc

eosio.

## package install

install

```bash
pip install git+https://github.com/ppolxda/pyeosio_ecc.git
```

## key_public examples

```python
# -*- coding: utf-8 -*-

from pyeosio_ecc.key_public import PublicKey


def main():
    pubkey = 'EOS8LSJ3oPe5KSY64Ds22Mw7sVWYHUYijEQKb8sBhfTQL7UTSLLZL'
    pubkey2 = PublicKey.from_string(pubkey)
    print(pubkey2.to_public())

    content = 'asdasdasdas'
    signdata = 'SIG_K1_K5mw15T3oMq2VEy4nxkWwPvTKxVBSTtKysyMoZq874QxuZo3ATfft3tK2gfZ39G2h3X4AcmmqXnCDZYJuxZgteMUXgbzYf'
    pubkey3 = PublicKey.recover(content, signdata)
    assert pubkey2.to_public() == pubkey3.to_public()


if __name__ == '__main__':
    main()

```

## link

[https://github.com/EOSIO/eosjs-ecc](https://github.com/EOSIO/eosjs-ecc)

[https://github.com/eosnewyork/eospy](https://github.com/EOSIO/eosjs-ecc)
