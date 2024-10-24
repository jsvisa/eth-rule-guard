# Eth-Rule-Guard

EthRuleGuard is a secure, rule-based system within the Ethereum ecosystem for controlling and safeguarding wallet signatures.

## Features

- **Ethereum Integration**: Seamlessly integrates with Ethereum networks for decentralized applications.
- **Rule Engine**: Customizable rules for fine-grained control over application behavior.
- **Wallet Control**: Secure management and control of Ethereum wallets.

## Rule Schemes

1. global scheme

```yaml
global:
  mode: denyall
  allow_create_contract: false
  allow_ether_transfer: false
```

2. contract related

For each contract, we have the below fields to config the WAF rules:

1. `name`: contract name(optional)
2. `address`: the contract address
3. `abi_file`: contract ABIS(only the function calls were required), for any Proxy contracts, also need the implementation contract's ABIs
4. `multicall`: allow `multicall` call, this will need the `multicall` ABI to decode into the actual function calls, and then we set rules on the actual function calls instead
5. `allowlist`: a full set of the allowed function calls

### How to set a rule

rules are set in the `allowlist` field, each rule has two fields:

1. `func`: the function name
2. `expr`: the rule expression, it's a boolean expression, if the expression is true, then the function call is allowed, otherwise denied.

eg:

1. swap's receiver address must be the same as the sender's address
2. transfer's max value should below 1 million
3. approve's value should not equal to infinity
4. swap slipage rate for the Dex swap should be meaningful
5. ...

### Examples

#### 1. USDT

```yaml
- name: USDT Token
  address: '0xdac17f958d2ee523a2206206994597c13d831ec7'
  abi_file: etc/waf/abi/USDT.json
  allowlist:
    - func: approve(address,uint256)
      expr: args._value < 100*1e6*1e6
    - func: transfer(address,uint256)
      expr: >
        args._value < 10*1e6*1e6
          and
        args._to not in [
          "0x0000000000000000000000000000000000000000",
          "0x00000000000000000000045261d4ee77acdb3286",
        ]
```

For the USDT contract, we only allow to invoke the `approve` and `transfer` functions, the others are denied.

Detail rules as below:

**rules**

1. allow call to `approve` with a maximum approved amount is 100Million USDT
2. allow call to `transfer` with a maximum transfered USDT amount is 10M and the destination address MUST not in the burned address.

#### 2. UniswapV2Router2

```yaml
- name: UniswapV2Router2
  address: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d'
  abi_file: etc/waf/abi/UniswapV2Router2.json
  allowlist:
    - func: swapETHForExactTokens(uint256,address[],address,uint256)
      expr: args.to == from_address
    - func: swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)
      expr: args.to == from_address
    - func: swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
      expr: args.to == from_address
    - func: swapTokensForExactTokens(uint256,uint256,address[],address,uint256)
      expr: args.to == from_address
    - func: swapExactTokensForETH(uint256,uint256,address[],address,uint256)
      expr: >
        args.to == from_address
          and
        args.path in [
          [ # USDC <-> WETH
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
          ],
          [ # USDT <-> WETH
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"],
        ]
```

For the UniswapV2Router2 contract, we only allow to invoke the below functions, the others are denied:

- `swapETHForExactTokens`,
- `swapExactTokensForETHSupportingFeeOnTransferTokens`,
- `swapExactTokensForTokens`,
- `swapTokensForExactTokens`
- `swapExactTokensForETH`

And the destination address MUST be the same as the source address.

#### 3. UniswapV3Router

```yaml
- name: UniswapV3Router
  address: '0xe592427a0aece92de3edee1f18e0157c05861564'
  multicall:
    - multicall(bytes[])
  abi_file: etc/waf/abi/UniswapV3Router.json
  allowlist:
    - func: exactOutput((bytes,address,uint256,uint256,uint256))
      expr: args.params.recipient == from_address
    - func: exactInput((bytes,address,uint256,uint256,uint256))
      expr: args.params.recipient in [from_address, '0x0000000000000000000000000000000000000000']

- name: UniswapV3Router2
  address: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45'
  multicall:
    - multicall(bytes[])
    - multicall(bytes32,bytes[])
    - multicall(uint256,bytes[])
  abi_file:
    - etc/waf/abi/UniswapV3Router2.json
    - etc/waf/abi/Multicall.json
  allowlist:
    - func: exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
      expr: args.params.recipient == from_address
```

Similar to the UniswapV2Router2 contract, we only allow to invoke the below functions, the others are denied, and only allow the destination address is the same as the source address.

#### 4. 1inchAggregationRouterV5

```yaml
- name: 1inchAggregationRouterV5
  address: '0x1111111254eeb25477b68fb85ed929f73a960582'
  abi_file: etc/waf/abi/1inchAggregationRouterV5.json
  allowlist:
    - func: uniswapV3Swap(uint256,uint256,uint256[])
      expr: 'true'
    - func: unoswap(address,uint256,uint256,uint256[])
      expr: 'true'
    - func: fillOrder((uint256,address,address,address,address,address,uint256,uint256,uint256,bytes),bytes,bytes,uint256,uint256,uint256)
      expr: 'true'
    - func: swap(address,(address,address,address,address,uint256,uint256,uint256),bytes,bytes)
      expr: args.desc.dstReceiver == from_address
```

1. allow the `uniswapV3Swap`, `unoswap` and `fillOrder` functions to call without any limitations

2. allow the `swap` function to call only when the `dstReceiver` is the same as the `from_address`

```json
{
  "data": "00000000000000000000000000000000000000000000017b00014d00010300a007e5c0d20000000000000000000000000000000000000000df0000c500008b00004f02a0000000000000000000000000000000000000000000000000710e6f932a0877a3ee63c1e50188e6a0c2ddd26feeb64f039a2c41296fcb3f5640a0b86991c6218b36c1d19d4a2e9eb0ce3606eb484101c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200042e1a7d4d00000000000000000000000000000000000000000000000000000000000000004060ae7ab96520de3a18e5e111b5eaab095312d7fe84a1903eab00000000000000000000000042f527f50f16a103b6ccab48bccca214500c10210020d6bdbf78ae7ab96520de3a18e5e111b5eaab095312d7fe8400a0f2fa6b66ae7ab96520de3a18e5e111b5eaab095312d7fe84000000000000000000000000000000000000000000000000748d900e7a8221990000000000000000000778f6fcb9ad7b80a06c4eca27ae7ab96520de3a18e5e111b5eaab095312d7fe841111111254eeb25477b68fb85ed929f73a960582",
  "desc": {
    "flags": 4,
    "amount": 20000000000,
    "dstToken": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
    "srcToken": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "dstReceiver": "0x3a3e8530693b871aedbd6e93db243badff39a197",
    "srcReceiver": "0xe37e799d5077682fa0a244d46e5649f71457bd09",
    "minReturnAmount": 8146571453815879585
  },
  "permit": "",
  "executor": "0xe37e799d5077682fa0a244d46e5649f71457bd09"
}
```

## References

### Rule Engine

Rule Engine is a powerful tool that allows users to define custom rules to filter and process data. It is a versatile system that can be used to implement a wide range of functionalities, from simple data validation to complex decision-making processes.

Supported operations as below.

#### Arithmetic Operators

| Operation | Description    | Compatible Data Types |
| --------- | -------------- | --------------------- |
| `+`       | Addition       | `FLOAT`               |
| `-`       | Subtraction    | `FLOAT`               |
| `*`       | Multiplication | `FLOAT`               |
| `**`      | Exponent       | `FLOAT`               |
| `/`       | True division  | `FLOAT`               |
| `//`      | Floor division | `FLOAT`               |
| `%`       | Modulo         | `FLOAT`               |

#### Bitwise-Arithmetic Operators

| Operation | Description         | Compatible Data Types |
| --------- | ------------------- | --------------------- |
| `&`       | Bitwise AND         | `FLOAT`, `SET`        |
| `\|`      | Bitwise OR          | `FLOAT`, `SET`        |
| `^`       | Bitwise XOR         | `FLOAT`, `SET`        |
| `>>`      | Bitwise right shift | `FLOAT`               |
| `<<`      | Bitwise left shift  | `FLOAT`               |

#### Comparison Operators

| Operation | Description  | Compatible Data Types |
| --------- | ------------ | --------------------- |
| `==`      | Equal to     | _ANY_                 |
| `!=`      | Not equal to | _ANY_                 |

#### Arithmetic-Comparison Operators

> Arithmetic comparison operators can compare different data types, but the data types on the left side must be the same as the data types on the right side.
> For example, you can compare two strings, but you cannot compare a string with a floating-point number.

| Operation | Description              | Compatible Data Types                                     |
| --------- | ------------------------ | --------------------------------------------------------- |
| `>`       | Greater than             | `ARRAY`, `BOOLEAN`, `DATETIME`, `FLOAT`, `NULL`, `STRING` |
| `>=`      | Greater than or equal to | `ARRAY`, `BOOLEAN`, `DATETIME`, `FLOAT`, `NULL`, `STRING` |
| `<`       | Less than                | `ARRAY`, `BOOLEAN`, `DATETIME`, `FLOAT`, `NULL`, `STRING` |
| `<=`      | Less than or equal to    | `ARRAY`, `BOOLEAN`, `DATETIME`, `FLOAT`, `NULL`, `STRING` |

#### Regex-Comparison Operators

| Operation | Description        | Compatible Data Types |
| --------- | ------------------ | --------------------- |
| `=~`      | Regex match        | `NULL`, `STRING`      |
| `=~~`     | Regex search       | `NULL`, `STRING`      |
| `!~`      | Regex match fails  | `NULL`, `STRING`      |
| `!~~`     | Regex search fails | `NULL`, `STRING`      |

#### Logical Operators

| Operation | Description      | Compatible Data Types |
| --------- | ---------------- | --------------------- |
| `and`     | Logical AND      | _ANY_                 |
| `not`     | Logical NOT      | _ANY_                 |
| `or`      | Logical OR       | _ANY_                 |
| `?`, `:`  | Ternary Operator | _ANY_                 |

#### Accessor Operators

| Operation | Description           | Compatible Data Types                            |
| --------- | --------------------- | ------------------------------------------------ |
| `.`       | Attribute access      | `ARRAY`, `DATETIME`, `MAPPING`, `STRING`         |
| `&.`      | Safe attribute access | `ARRAY`, `DATETIME`, `MAPPING`, `NULL`, `STRING` |
| `[`       | Item lookup           | `ARRAY`, `MAPPING`, `STRING`                     |
| `&[`      | Safe item lookup      | `ARRAY`, `MAPPING`, `NULL`, `STRING`             |
| `.length` | Length                | `ARRAY`, `SET`, `MAPPING`                        |
| `[]`      | Array construct       | `ARRAY`, `SET`                                   |
