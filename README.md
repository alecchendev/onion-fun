# onion-fun

A basic implementation of sphinx/route-blinding for grokking purposes.
The crypto was the main focus; the serialization is mainly a placeholder.

Some resources that were helpful while making this:

- [BOLT 4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [Route blinding proposal](https://github.com/lightning/bolts/blob/master/proposals/route-blinding.md)
- [Sphinx onion encryption: from Zero to Hero](https://github.com/t-bast/lightning-docs/blob/master/sphinx.md)

Run from root directory:

```
python3 -m venv <venv-name>
source <venv-name>/bin/activate
pip install -r requirements.txt
python3 -m unittest main.py
```
