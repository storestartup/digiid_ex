defmodule Digibyte.Core do
  use Bitwise
  alias Digibyte.U

  @typedoc """
    binary encoded key: "bin", "bin_compressed"
  """
  @type binary_encoded_key() :: list(byte)
  @typedoc """
    hex encoded key: "hex", "hex_compressed"
  """
  @type hex_encoded_key() :: String.t()
  @typedoc """
    "wif", "wif_compressed"
  """
  @type wif_encoded_key() :: String.t()
  @typedoc """
    native decoded key in big integer, or "decimal"
  """
  @type native_key() :: non_neg_integer
  @type native_private_key() :: native_key()
  @type native_public_key() :: native_key()
  @type native_public_key_pair() :: {native_key(), native_key()}

  @type binary_encoded_private_key() :: binary_encoded_key()
  @type hex_encoded_private_key() :: hex_encoded_key()
  @type wif_encoded_private_key() :: wif_encoded_key()
  @type binary_encoded_public_key() :: binary_encoded_key()
  @type hex_encoded_public_key() :: hex_encoded_key()

  @type encoded_private_key() :: binary_encoded_private_key() | hex_encoded_private_key() | wif_encoded_private_key()
  @type encoded_public_key() :: binary_encoded_public_key() | hex_encoded_public_key()
  @type encoded_key() :: binary_encoded_key() | hex_encoded_key() | wif_encoded_key()

  @typedoc """
    b58checked public address string
  """
  @type address :: String.t()

  @typedoc """
    "bin" | "bin_compressed" | "bin_electrum" | "decimal" | "hex" | "hex_compressed" | "hex_electrum"
  """
  @type public_key_format() :: String.t()
  @typedoc """
    "bin" | "bin_compressed" | "bin_electrum" | "decimal" | "hex" | "hex_compressed" | "hex_electrum" | "wif" | "wif_compressed"
  """
  @type private_key_format() :: String.t()

  # p = 2 ^ 256 - 2 ^ 32 - 977
  @_p 115792089237316195423570985008687907853269984665640564039457584007908834671663

  @doc """
    secp256k1 prime
  """
  def p,  do: @_p
  def _p, do: @_p

  @_n 115792089237316195423570985008687907852837564279074904382605163141518161494337
  @doc """
    secp256k1 number of points
  """
  def n, do: @_n
  def _n, do: @_n

  @_a 0
  @doc """
    secp256k1 y^2 = x^3 + ax + b, a is 0
  """
  def a, do: @_a
  def _a, do: a()

  @_b 7
  @doc """
    secp256k1 y^2 = x^3 + ax + b, b is 7
  """
  def b, do: @_b
  def _b, do: b()

  @_g_x 55066263022277343669578718895168534326250603453777594175500187360389116729240
  @_g_y 32670510020758816978083085130507043184471273380659243275938904335757337482424
  @_g {@_g_x, @_g_y}

  @doc """
    secp256k1 base point (G) = (g_x, g_y)
  """
  def g_x, do: @_g_x
  @doc """
    secp256k1 base point (G) = (g_x, g_y)
  """
  def g_y, do: @_g_y
  @doc """
    secp256k1 base point (G) = (g_x, g_y)
  """
  def g, do: {g_x(), g_y()}
  def _g, do: g()

  defp _inv(n, lm, _, low, _) when low <= 1, do: U.mod(lm, n)
  defp _inv(n, lm, hm, low, high) do
    r = div(high, low)
    {nm, new} = {hm - lm * r, high - low * r}
    _inv(n, nm, lm, new, low)
  end

  @doc """
    extended Euclidean algo
  """
  def inv(0, _), do: 0
  def inv(a, n) do
    {lm, hm} = {1, 0}
    {low, high} = {U.mod(a, n), n}
    _inv(n, lm, hm, low, high)
  end

  @spec is_inf(pair) :: boolean
  def is_inf(p) do
    elem(p, 0) == 0 and elem(p, 1) == 0
  end

  #
  # Jacobian
  #

  @typedoc """
    jacobian number as a tuple
  """
  @type jacobian_number :: {non_neg_integer, non_neg_integer, non_neg_integer}

  @typedoc """
    point on the elliptic curve as a tuple
  """
  @type pair :: {non_neg_integer, non_neg_integer}

  @spec to_jacobian(pair) :: {non_neg_integer, non_neg_integer, 1}
  def to_jacobian(p) do
    {elem(p, 0), elem(p, 1), 1}
  end

  @spec jacobian_double(jacobian_number) :: jacobian_number
  def jacobian_double(p) do
    case elem(p, 1) do
      0 ->
        {0, 0, 0}

      _ ->
        ysq = U.mod(U.power(elem(p, 1), 2), _p())
        s = U.mod(4 * elem(p, 0) * ysq, _p())
        m = U.mod(3 * U.power(elem(p, 0), 2) + _a() * U.power(elem(p, 2), 4), _p())
        nx = U.mod(U.power(m, 2) - 2 * s, _p())
        ny = U.mod(m * (s - nx) - 8 * ysq * ysq, _p())
        nz = U.mod(2 * elem(p, 1) * elem(p, 2), _p())
        {nx, ny, nz}
    end
  end

  @spec jacobian_add(jacobian_number, jacobian_number) :: jacobian_number
  def jacobian_add(p, q) do
    case {elem(p, 1), elem(q, 1)} do
      {0, _} ->
        q

      {_, 0} ->
        p

      _ ->
        u1 = U.mod(elem(p, 0) * elem(q, 2) * elem(q, 2), _p())
        u2 = U.mod(elem(q, 0) * elem(p, 2) * elem(p, 2), _p())
        s1 = U.mod(elem(p, 1) * U.power(elem(q, 2), 3), _p())
        s2 = U.mod(elem(q, 1) * U.power(elem(p, 2), 3), _p())

        if u1 == u2 do
          if s1 != s2 do
            {0, 0, 1}
          else
            jacobian_double(p)
          end
        else
          h = u2 - u1
          r = s2 - s1
          h2 = U.mod(h * h, _p())
          h3 = U.mod(h * h2, _p())
          u1h2 = U.mod(u1 * h2, _p())
          nx = U.mod(r * r - h3 - 2 * u1h2, _p())
          ny = U.mod(r * (u1h2 - nx) - s1 * h3, _p())
          nz = U.mod(h * elem(p, 2) * elem(q, 2), _p())
          {nx, ny, nz}
        end
    end
  end

  @spec from_jacobian(jacobian_number) :: pair
  def from_jacobian(p) do
    z = inv(elem(p, 2), _p())
    {U.mod(elem(p, 0) * U.power(z, 2), _p()), U.mod(elem(p, 1) * U.power(z, 3), _p())}
  end

  @spec jacobian_multiply(jacobian_number, jacobian_number) :: jacobian_number
  def jacobian_multiply(a, n) do
    cond do
      elem(a, 1) == 0 or n == 0 ->
        {0, 0, 1}

      n == 1 ->
        a

      n < 0 or n >= _n() ->
        jacobian_multiply(a, U.mod(n, _n()))

      U.mod(n, 2) == 0 ->
        jacobian_double(jacobian_multiply(a, div(n, 2)))

      U.mod(n, 2) == 1 ->
        jacobian_add(jacobian_double(jacobian_multiply(a, div(n, 2))), a)
    end
  end

  @spec fast_multiply(pair, non_neg_integer) :: pair
  def fast_multiply(a, n) do
    from_jacobian(jacobian_multiply(to_jacobian(a), n))
  end

  @spec fast_add(pair, pair) :: pair
  def fast_add(a, b) do
    from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))
  end

  @spec get_pubkey_format(encoded_public_key() | native_public_key_pair()) :: public_key_format()
  def get_pubkey_format(key) do
    cond do
      is_tuple(key) ->
        "decimal"

      is_list(key) ->
        # charlist
        size = length(key)
        cond do
          size == 65 and List.first(key) == 4 ->
            "bin"

          size == 33 and List.first(key) in [2, 3] ->
            "bin_compressed"

          size == 64 ->
            "bin_electrum"

          true ->
            raise "Pubkey not in regonized format"
        end

      is_bitstring(key) ->
        # String key
        size = byte_size(key)
        cond do
          size == 130 and String.slice(key, 0, 2) == "04" ->
            "hex"

          size == 66 and String.slice(key, 0, 2) in ["02", "03"] ->
            "hex_compressed"

          size == 128 ->
            "hex_electrum"

          true ->
            raise "Pubkey not in regonized format"
        end

      true ->
        raise "Pubkey not in regonized format"
    end
  end

  @spec is_pubkey(encoded_public_key | native_public_key_pair) :: boolean
  def is_pubkey(key) do
    get_pubkey_format(key) && true
  end

  @spec get_privkey_format(encoded_private_key | native_private_key) :: private_key_format
  def get_privkey_format(key) do
    cond do
      is_number(key) ->
        "decimal"

      is_list(key) or is_bitstring(key) ->
        size =
          if is_list(key) do
            length(key)
          else
            String.length(key)
          end

        case size do
          32 ->
            "bin"

          33 ->
            "bin_compressed"

          64 ->
            "hex"

          66 ->
            "hex_compressed"

          _  ->
            bin_p = b58check_to_bin(key)

            case length(bin_p) do
              32 -> "wif"
              33 -> "wif_compressed"
              _ -> raise "WIF does not represent private key"
            end
        end

      true ->
        raise "Invalid private key format"
    end
  end

  @spec is_privkey(encoded_private_key | native_private_key) :: boolean
  def is_privkey(key) do
    get_privkey_format(key) && true
  end

  @spec decode_privkey(encoded_private_key | native_private_key, private_key_format | nil) :: native_private_key
  def decode_privkey(key, format \\ nil) do
    format = format || get_privkey_format(key)
    case format do
      "decimal" ->
        key

      "bin" ->
        decode(key, 256)

      "bin_compressed" ->
        decode(Enum.slice(key, 0..31), 256)

      "hex" ->
        decode(key, 16)

      "hex_compressed" ->
        decode(String.slice(key, 0..63), 16)

      "wif" ->
        decode(b58check_to_bin(key), 256)

      "wif_compressed" ->
        decode(Enum.slice(b58check_to_bin(key), 0..31), 256)

      _ ->
        raise "WIF does not represent privkey"
    end
  end

  @spec encode_privkey(encoded_private_key | native_private_key, private_key_format, integer) :: encoded_private_key
  def encode_privkey(key, format, vbyte \\ 0) do
    cond do
      not is_number(key) ->
        encode_privkey(decode_privkey(key), format, vbyte)

      format == "decimal" ->
        key

      format == "bin" ->
        encode(key, 256, 32)

      format == "bin_compressed" ->
        encode(key, 256, 32) ++ [1]

      format == "hex" ->
        encode(key, 16, 64)

      format == "hex_compressed" ->
        encode(key, 16, 64) <> "01"

      format == "wif" ->
        bin_to_b58check(encode(key, 256, 32), 128 + vbyte)

      format == "wif_compressed" ->
        bin_to_b58check(encode(key, 256, 32) ++ [1], 128 + vbyte)

      true ->
        raise "not implemented"
    end
  end

  @spec add_pubkeys(encoded_public_key, encoded_public_key) :: encoded_public_key
  def add_pubkeys(p1, p2) do
    {format1, format2} = {get_pubkey_format(p1), get_pubkey_format(p2)}
    encode_pubkey(fast_add(decode_pubkey(p1, format1), decode_pubkey(p2, format2)), format1)
  end

  @spec add_privkeys(encoded_private_key, encoded_private_key) :: encoded_private_key
  def add_privkeys(p1, p2) do
    {format1, format2} = {get_privkey_format(p1), get_privkey_format(p2)}
    encode_privkey(U.mod(decode_privkey(p1, format1) + decode_privkey(p2, format2), @_n), format1)
  end

  @spec add(p1 :: encoded_key, p2 :: encoded_key) :: encoded_private_key | encoded_public_key
  def add(p1, p2) do
    cond do
      is_privkey(p1) ->
        add_privkeys(p1, p2)

      true ->
        add_pubkeys(p1, p2)
    end
  end

  @spec multiply_privkeys(p1 :: encoded_private_key, p2 :: encoded_private_key) :: encoded_private_key
  def multiply_privkeys(p1, p2) do
    {format1, format2}= {get_privkey_format(p1), get_privkey_format(p2)}
    encode_privkey(U.mod(decode_privkey(p1, format1) * decode_privkey(p2, format2), @_n), format1)
  end

  @spec multiply(encoded_public_key, encoded_private_key | native_private_key) :: encoded_public_key | native_public_key
  def multiply(pubkey, privkey) do
    {format1, format2} = {get_pubkey_format(pubkey), get_privkey_format(privkey)}
    {pubkey, privkey} = {decode_pubkey(pubkey, format1), decode_privkey(privkey, format2)}
    {pub0, pub1} = pubkey
    if not is_inf(pubkey) and U.mod(U.power(pub0, 3) + @_b - pub1 * pub1, @_p) != 0 do
      raise "Point not on curve"
    else
      encode_pubkey(fast_multiply(pubkey, privkey), format1)
    end
  end

  @spec divide(encoded_public_key, encoded_private_key | native_private_key) :: encoded_public_key | native_public_key
  def divide(pubkey, privkey) do
    multiply(pubkey, inv(decode_privkey(privkey), @_n))
  end

  @doc """
    returns "bin_compressed" or "hex_compressed" version of the public key if possible.
  """
  @spec compress(encoded_public_key | native_public_key) :: encoded_public_key
  def compress(pubkey) do
    case get_pubkey_format(pubkey) do
      "bin" ->
        encode_pubkey(decode_pubkey(pubkey, "bin"), "bin_compressed")
      f when f in ["hex", "decimal"] ->
        encode_pubkey(decode_pubkey(pubkey, f), "hex_compressed")
      _ ->
        pubkey
    end
  end

  @doc """
    returns the un-compressed version of the public key, i.e. "bin" or "hex"
  """
  @spec decompress(encoded_public_key | native_public_key) :: encoded_public_key
  def decompress(pubkey) do
    case get_pubkey_format(pubkey) do
      "bin_compressed" ->
        encode_pubkey(decode_pubkey(pubkey, "bin_compressed"), "bin")
      f when f in ["hex_compressed", "decimal"] ->
        encode_pubkey(decode_pubkey(pubkey, f), "hex")
      _ ->
        pubkey
    end
  end

  @spec pubkey_to_address(
          native_public_key_pair | encoded_public_key | native_public_key,
          non_neg_integer
        ) :: address
  def pubkey_to_address(pubkey, magicbyte \\ 0) do
    pubkey
    |> Base.decode16!(case: :lower)
    |> bin_hash160()
    |> bin_to_b58check(magicbyte)
  end

  @spec privkey_to_pubkey(encoded_private_key | native_private_key) :: encoded_public_key | native_public_key | native_public_key_pair
  def privkey_to_pubkey(key) do
    format = get_privkey_format(key)
    decoded_key = decode_privkey(key, format)
    decoded_key < @_n or raise "Invalid private key"
    if format in ["bin", "bin_compressed", "hex", "hex_compressed", "decimal"] do
      encode_pubkey(fast_multiply(@_g, decoded_key), format)
    else
      encode_pubkey(fast_multiply(@_g, decoded_key), String.replace(format, "wif", "hex"))
    end
  end

  @spec privkey_to_address(encoded_private_key | native_private_key, integer) :: address
  def privkey_to_address(key, magicbyte \\ 0) do
    pubkey_to_address(privkey_to_pubkey(key), magicbyte)
  end

  @spec is_address(address) :: boolean
  def is_address(address) do
    Regex.match?(~r/^[D|3|dgb1|S][a-km-zA-HJ-NP-Z0-9]{26,33}$/, address)
  end

  @spec neg_pubkey(encoded_public_key | native_public_key) :: encoded_public_key
  def neg_pubkey(key) do
    format = get_pubkey_format(key)
    pk = decode_pubkey(key, format)
    encode_pubkey({elem(pk, 0), U.mod(@_p - elem(pk, 1), @_p)}, format)
  end

  @spec neg_privkey(encoded_private_key | native_private_key) :: encoded_private_key | native_private_key
  def neg_privkey(key) do
    format = get_privkey_format(key)
    pk = decode_privkey(key, format)
    encode_privkey(U.mod(@_n - pk, @_n), format)
  end

  @spec subtract_pubkeys(encoded_public_key, encoded_public_key) :: encoded_public_key
  def subtract_pubkeys(p1, p2) do
    {format1, format2} = {get_pubkey_format(p1), get_pubkey_format(p2)}
    k = decode_pubkey(p2, format2)
    encode_pubkey(fast_add(decode_pubkey(p1, format1), {elem(k, 0), U.mod(@_p - elem(k, 1), @_p)}), format1)
  end

  @spec subtract_privkey(encoded_private_key | native_private_key, encoded_private_key | native_private_key) :: encoded_private_key | native_private_key
  def subtract_privkey(p1, p2) do
    {format1, format2} = {get_privkey_format(p1), get_privkey_format(p2)}
    k = decode_privkey(p2, format2)
    encode_privkey(U.mod(decode_privkey(p1, format1) - k, @_n), format1)
  end

  @spec substract(p1 :: encoded_private_key | encoded_public_key | native_private_key | native_public_key,
          p2 :: encoded_private_key | encoded_public_key | native_private_key | native_public_key
        ) :: encoded_private_key | encoded_public_key | native_private_key | native_public_key
  def substract(p1, p2) do
    cond do
      is_privkey(p1) ->
        subtract_privkey(p1, p2)

      true ->
        subtract_pubkeys(p1, p2)
    end
  end

  @spec encode_pubkey(native_public_key_pair, public_key_format) :: encoded_public_key | native_public_key_pair
  def encode_pubkey(pub, format) do
    {one, two} = pub
    case format do
      "decimal" ->
        pub

      "bin" ->
        [4] ++ encode(one, 256, 32) ++ encode(two, 256, 32)

      "bin_compressed" ->
        is_odd = U.mod(two, 2)
        [2 + U.mod(two, 2)] ++ encode(one, 256, 32)

      "hex" ->
        "04" <> encode(one, 16, 64) <> encode(two, 16, 64)

      "hex_compressed" ->
        "0" <> to_string(2 + U.mod(two, 2)) <> encode(one, 16, 64)

      "bin_electrum" ->
        encode(one, 256, 32) ++ encode(two, 256, 32)

      "hex_electrum" ->
        encode(one, 16, 64) <> encode(two, 16, 64)

      _ ->
        raise "Invalid format #{format}"
    end
  end

  @spec decode_pubkey(encoded_public_key, public_key_format) :: native_public_key_pair
  def decode_pubkey(pub, format \\ nil ) do
    format = format || get_pubkey_format(pub)
    case format do
      "bin" ->
        {decode(Enum.slice(pub, 1..32), 256), decode(Enum.slice(pub, 33..64), 256)}

      "bin_compressed" ->
        x = decode(Enum.slice(pub, 1..32), 256)
        beta = U.power(x * x * x + _a() * x + _b(), div(_p() + 1, 4), @_p)
        y =
          if U.mod(beta + Enum.at(pub, 0), 2) == 1 do
            @_p - beta
          else
            beta
          end
        {x, y}

      "hex" ->
        {decode(String.slice(pub, 2..65), 16), decode(String.slice(pub, 66..129), 16)}

      "hex_compressed" ->
        x = decode(String.slice(pub, 2..65), 16)
        beta = U.power(x * x * x + _a() * x + _b(), div(_p() + 1, 4), @_p)
        y =
          if U.mod(beta + Enum.at(String.to_charlist(pub), 0), 2) == 1 do
            @_p - beta
          else
            beta
          end
        # FYI this had to be changed to work, otherwise y was result in wrong value
        # and broke the address from pubkey
        # TODO need to test with other addresses
        #{x, beta}
        {x, y}

      "bin_electrum" ->
        {decode(Enum.slice(pub, 0..31), 256), decode(Enum.slice(pub, 32..63), 256)}

      "hex_electrum" ->
        {decode(String.slice(pub, 0..63), 16), decode(String.slice(pub, 64..127), 16)}

      _ ->
        raise "Invalid format #{format}"
    end
  end

  ###############
  # common
  ###############

  @spec bin_hash160(list(byte)) :: list(byte)
  def bin_hash160(chars) do
    tmp = :crypto.hash(:sha256, chars)
    :binary.bin_to_list(:crypto.hash(:ripemd160, tmp))
  end

  @spec bin_sha256(list(byte)) :: list(byte)
  def bin_sha256(chars) do
    :binary.bin_to_list(:crypto.hash(:sha256, chars))
  end

  @doc """
    iex> C.sha256('784734adfids')
    "ae616f5c8f6d338e4905f6170a90a231d0c89470a94b28e894a83aef90975557"
  """
  @spec sha256(list(byte) | bitstring | binary | String.t()) :: String.t()
  def sha256(chars) do
    bytes_to_hex_string(:crypto.hash(:sha256, chars))
  end

  @spec bin_ripemd160(list(byte) | bitstring | binary | String.t()) :: list(byte)
  def bin_ripemd160(chars) do
    :binary.bin_to_list(:crypto.hash(:ripemd160, chars))
  end

  @spec b58check_to_bin(hex_encoded_key | wif_encoded_key) :: binary_encoded_key
  def b58check_to_bin(key) do
    leadingzbytes = case Regex.named_captures(~r/^(?<ones>1*)/, key) do
      %{"ones" => d} ->
        String.length(d)

      _ ->
        0
    end
    data = U.replicate(leadingzbytes, 0) ++ changebase(key, 58, 256)
    size = length(data)

    if Enum.slice(bin_double_sha256(Enum.slice(data, 0..size-5)), 0..3) == Enum.slice(data, size-4..size-1) do
      Enum.slice(data, 1..size-5)
    else
      raise "Assertion failed for bin_double_sha256 #{key}"
    end
  end

  defp _bin_to_b58check(chars, 0), do: [ 0 ] ++ chars

  defp _bin_to_b58check(chars, magic_byte) do
    r = U.mod(magic_byte, 256)
    magic_byte = div(magic_byte, 256)
    cond do
      magic_byte > 0 ->
        _bin_to_b58check([r] ++ chars, magic_byte)

      true ->
        [r] ++ chars
    end
  end

  @spec bin_to_b58check(binary_encoded_key, integer) :: binary_encoded_key
  def bin_to_b58check(chars, magic_byte \\ 0) do
    chars = _bin_to_b58check(chars, magic_byte)
    leadingzbytes = case Enum.find_index(chars, fn x -> x != 0 end) do
      nil ->
        0

      idx ->
        idx
    end
    checksum = Enum.slice(bin_double_sha256(chars), 0..3)
    U.replicate(leadingzbytes, "1") <> changebase(chars ++ checksum, 256, 58)
  end

  @spec bin_double_sha256(list(byte) | binary | bitstring | String.t()) :: list(byte)
  def bin_double_sha256(chars) do
    hash = :crypto.hash(:sha256, chars)
    # hash is <<118, 134, ... >>
    :binary.bin_to_list(:crypto.hash(:sha256, hash))
  end

  @spec bin_slowsha(list(byte)) :: list(byte)
  def bin_slowsha(chars) do
    Stream.iterate(chars, &(:binary.bin_to_list(:crypto.hash(:sha256, &1 ++ chars)))) |> Enum.at(100000)
  end

  @spec slowsha(list(byte)) :: String.t()
  def slowsha(chars) do
    bytes_to_hex_string(:binary.list_to_bin(bin_slowsha(chars)))
  end

  @spec hash_to_int(String.t() | list(byte)) :: integer
  def hash_to_int(x) do
    size =
      if is_list(x) do
        length(x)
      else
        String.length(x)
      end
    case size do
      n when n == 40 or n == 64 ->
        decode(x, 16)

      _ ->
        decode(x, 256)
    end
  end

  @spec num_to_var_int(integer) :: list(byte)
  def num_to_var_int(x) do
    cond do
      x < 253 ->
        [x]

      x < 65536 ->
        [253] ++ Enum.reverse(encode(x, 256, 2))

      x < 4294967296 ->
        [254] ++ Enum.reverse(encode(x, 256, 4))

      true ->
        [255] ++ Enum.reverse(encode(x, 256, 8))
    end
  end

  @spec random_key() :: String.t()
  def random_key() do
    (:crypto.strong_rand_bytes(32) |> :binary.bin_to_list) ++
      Integer.to_charlist(:rand.uniform(U.power(2,256))) ++
      Integer.to_charlist(System.system_time(:microsecond))
    |> sha256
  end

  @spec electrum_sig_hash(String.t()) :: list(byte)
  def electrum_sig_hash(message) do
    [25] ++ 'DigiByte Signed Message:\n' ++ num_to_var_int(String.length(message)) ++ String.to_charlist(message)
    |> bin_double_sha256
  end

  @spec random_electrum_seed() :: String.t()
  def random_electrum_seed() do
    random_key() |> String.slice(0..31)
  end

  #
  # EDCSA
  #

  @spec encode_sig(integer, integer, integer) :: String.t()
  def encode_sig(v, r, s) do
    {vb, rb, sb} = {[v], encode(r, 256), encode(s, 256)}
    vb ++ U.replicate(32 - length(rb), 0) ++ rb ++ U.replicate(32 - length(sb), 0) ++ sb
    |> :binary.list_to_bin # use :binary.list_to_bin, not List.to_string which expects utf-8 codepoints
    |> Base.encode64
  end

  @spec decode_sig(String.t()) :: {integer, integer, integer}
  def decode_sig(signature) do
    {:ok, bitstr} = Base.decode64(signature)
    integers = :binary.bin_to_list(bitstr)
    {Enum.at(integers, 0), decode(Enum.slice(integers, 1..32), 256), decode(Enum.slice(integers, 33..length(integers)-1), 256)}
  end

  @spec deterministic_generate_k(String.t(), String.t()) :: non_neg_integer
  def deterministic_generate_k(msg_hash, privkey) do
    v = U.replicate(32, 1)
    k = U.replicate(32, 0)
    priv = encode_privkey(privkey, "bin")
    msg_hash = encode(hash_to_int(msg_hash), 256, 32)

    k = :binary.bin_to_list(:crypto.hmac(:sha256, k, v ++ [ 0 ] ++ priv ++ msg_hash))
    v = :binary.bin_to_list(:crypto.hmac(:sha256, k, v))
    k = :binary.bin_to_list(:crypto.hmac(:sha256, k, v ++ [ 1 ] ++ priv ++ msg_hash))
    v = :binary.bin_to_list(:crypto.hmac(:sha256, k, v))
    decode(:binary.bin_to_list(:crypto.hmac(:sha256, k, v)), 256)
  end

  @spec ecdsa_raw_sign(String.t() | charlist, String.t() | non_neg_integer) :: {non_neg_integer, non_neg_integer, non_neg_integer}
  def ecdsa_raw_sign(msg_hash, privkey) do
    z = hash_to_int(msg_hash)
    k = deterministic_generate_k(msg_hash, privkey)
    {r, y} = fast_multiply(@_g, k)
    s = U.mod(inv(k, @_n) * (z + r * decode_privkey(privkey)), @_n)
    v = 27 + (U.mod(y, 2) ^^^ (if s * 2 < @_n, do: 0, else: 1))
    s = if s * 2 >= @_n, do: @_n - s, else: s
    v = if get_privkey_format(privkey) in [ "hex_compressed", "bin_compressed" ], do: v + 4, else: v
    {v, r, s}
  end

  @spec ecdsa_sign(String.t(), String.t()) :: String.t()
  def ecdsa_sign(msg, privkey) do
    {v, r, s} = ecdsa_raw_sign(electrum_sig_hash(msg), privkey)
    sig = encode_sig(v, r, s)
    if not ecdsa_verify(msg, sig, privkey_to_pubkey(privkey)) do
      raise "Bad signature! #{sig}\nv = #{v}\n,r = #{r}\ns = #{s}"
    else
      sig
    end
  end

  @spec ecdsa_raw_verify(list(byte), {non_neg_integer, non_neg_integer, non_neg_integer}, String.t() | pair) :: boolean
  def ecdsa_raw_verify(msg_hash, {v, r, s}, pubkey) do
    if not (v >= 27 and v <= 34) do
      false
    else
      w = inv(s, @_n)
      z = hash_to_int(msg_hash)
      {u1, u2} = {U.mod(z * w, @_n), U.mod(r * w, @_n)}
      {x, _} = fast_add(fast_multiply(@_g, u1), fast_multiply(decode_pubkey(pubkey), u2))

      if r == x && U.mod(r, @_n) != 0 && U.mod(s, @_n) != 0 do
        true
      else
        false
      end
    end
  end

  @doc """
    recover the public key
  """
  @spec ecdsa_raw_recover(charlist, {non_neg_integer, non_neg_integer, non_neg_integer}) :: pair
  def ecdsa_raw_recover(msg_hash, {v, r, s}) do
    if not (v >= 27 and v <=34) do
      raise "#{v} must be in range 27 to 34"
    else
      x = r
      x_cubed_axb = U.mod(x * x * x + @_a * x + @_b, @_p)
      beta = U.power(x_cubed_axb, div(@_p + 1, 4), @_p)
      y = if U.mod(v, 2) ^^^ U.mod(beta, 2) != 0 do
        beta
      else
        @_p - beta
      end
      if U.mod(x_cubed_axb - y*y, @_p) != 0 || U.mod(r, @_n) == 0 || U.mod(s, @_n) == 0 do
        raise "Invalid message hash #{msg_hash}"
      else
        z = hash_to_int(msg_hash)
        gz = jacobian_multiply({@_g_x, @_g_y, 1}, U.mod(@_n - z, @_n))
        xy = jacobian_multiply({x, y, 1}, s)
        qr = jacobian_add(gz, xy)
        q = jacobian_multiply(qr, inv(r, @_n))
        from_jacobian(q)
      end
    end
  end

  @spec ecdsa_recover(String.t(), String.t()) :: String.t()
  def ecdsa_recover(msg, signature) do
    {v, r, s} = decode_sig(signature)
    q = ecdsa_raw_recover(electrum_sig_hash(msg), {v, r, s})
    if v >= 31 do
      encode_pubkey(q, "hex_compressed")
    else
      encode_pubkey(q, "hex")
    end
  end

  @spec get_version_byte(String.t()) :: integer
  def get_version_byte(address) do
    leadingzbytes = case Regex.named_captures(~r/^(?<ones>1*)/, address) do
      %{"ones" => d} ->
        String.length(d)

      _ ->
        0
    end
    data = U.replicate(leadingzbytes, 0) ++ changebase(address, 58, 256)
    size = length(data)
    if not (Enum.slice(bin_double_sha256(Enum.slice(data, 0..size-5)), 0..3) == Enum.slice(data, size-4..size-1)) do
      raise "Assertion failed for get_version_byte #{address}"
    else
      Enum.at(data, 0)
    end
  end

  @spec ecdsa_verify_address(String.t(), String.t(), String.t()) :: boolean
  def ecdsa_verify_address(msg, signature, address) do
    if not is_address(address) do
      false
    else
      q = ecdsa_recover(msg, signature)
      magic = get_version_byte(address)
      address == pubkey_to_address(q, magic) || (address == pubkey_to_address(compress(q), magic))
    end
  end

  @spec ecdsa_verify(String.t(), String.t(), String.t()) :: boolean
  def ecdsa_verify(msg, sig, pub) do
    if is_address(pub) do
      ecdsa_verify_address(msg, sig, pub)
    else
      ecdsa_raw_verify(electrum_sig_hash(msg), decode_sig(sig), pub)
    end
  end


  @code_strings %{
    2 => '01',
    10 => '0123456789',
    16 => '0123456789abcdef',
    32 => 'abcdefghijklmnopqrstuvwxyz234567',
    58 => '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256 => 255..0 |> Enum.reduce([], fn(x, acc) -> [ x | acc ] end)
  }

  @typedoc """
    use charlist to represent code strings
  """
  @type code_string :: charlist
  def code_strings, do: @code_strings

  @type code_base :: 2 | 10 | 16 | 32 | 58 | 256

  @spec get_code_string(integer) :: code_string
  def get_code_string(base) do
    if base in Map.keys(@code_strings) do
      Map.get(@code_strings, base)
    else
      raise "Invalid base #{base}"
    end
  end

  @spec _encode(non_neg_integer, integer, charlist, list) :: charlist
  defp _encode(0, _, _, acc), do: acc
  defp _encode(val, base, code_str, acc) do
    code = Enum.at(code_str, U.mod(val, base))
    _encode(div(val, base), base, code_str, [ code | acc ])
  end

  @doc """
    anything non base 256 is encoded as a string format of the target chars (base 16, base 10 or base 2);
    base 256 is encoded as a list(byte)

      iex> prime_70 = 4669523849932130508876392554713407521319117239637943224980015676156491
      iex> assert encode(prime_70, 58) == "8s3gRRbpi7NyJH3sudQTtsygDHDyzzB5q3Xc6svA"
      iex> assert encode(prime_70, 32) == "cwthr5r3cy4jn6as3oouomr3ondgjigwie45geqegagy2sl"
      iex> assert encode(prime_70, 256) == [173, 51, 199, 177, 216, 177, 196, 183, 192, 150, 220, 234, 57, 145, 219, 154, 51, 37, 6, 178, 9, 206, 152, 144, 33, 128, 108, 106, 75]
  """
  @spec encode(non_neg_integer, integer, pos_integer) :: String.t() | list(byte)
  def encode(val, base, minlen \\ 0) do
    code_str = get_code_string(base)
    results_bytes = _encode(val, base, code_str, [])
    pad_size = minlen - length(results_bytes)

    padding_element = case base do
      256 -> 0
       58 -> ?1
       _  -> ?0
    end

    results_bytes = cond do
      pad_size > 0 ->
        U.replicate(pad_size, padding_element) ++ results_bytes
      true ->
        results_bytes
    end

    if base == 256 do
      results_bytes
    else
      List.to_string(results_bytes)
    end
  end

  @spec _decode(charlist, integer, charlist, non_neg_integer) :: non_neg_integer
  defp _decode([], _, _, acc), do: acc
  defp _decode(chars, base, code_str, acc) do
    [ch | tail ] = chars
    acc = acc * base
    acc = acc + Enum.find_index(code_str, fn(c) -> c == ch end)
    _decode(tail, base, code_str, acc)
  end

  @doc """
    Decode a base-N encoded string into the equivalent integer

      iex> prime_70 = 4669523849932130508876392554713407521319117239637943224980015676156491
      iex> assert decode("8s3gRRbpi7NyJH3sudQTtsygDHDyzzB5q3Xc6svA", 58) == prime_70
      iex> assert decode("11111100101010110000110110010111001110001101001111111101010000101", 2) == prime_20
  """
  @spec decode(String.t() | list(byte), code_base) :: non_neg_integer
  def decode(val, base) do
    code_str = get_code_string(base)
    char_list = case base do
      256 ->
        val
      _ ->
        String.to_charlist(val)
    end
    _decode(char_list, base, code_str, 0)
  end

  def lpad(msg, symbol, len) do
    if String.length(msg) >= len do
      msg
    else
      U.replicate(len - String.length(msg), symbol) <> msg
    end
  end

  @doc """
    Convert encoded string between different base, e.g. base-2, base-10, base-16 etc
  """
  @spec changebase(str :: String.t() | list(byte), from :: code_base, to :: code_base, minlen :: integer) :: String.t() | list(byte)
  def changebase(str, from, to, minlen \\ 0) do
    cond do
      from == to ->
        lpad(str, String.at(List.to_string(get_code_string(from)), 0), minlen)
      true ->
        encode(decode(str, from), to, minlen)
    end
  end

  @doc """
    the term `bytes` in Python 3 is used as `charlist` in naming the method and argument here
  """
  def from_string_to_bytes(s) do
    String.to_charlist(s)
  end

  @spec bytes_to_hex_string(binary) :: String.t()
  def bytes_to_hex_string(bin) do
    Base.encode16(bin, case: :lower)
  end

end
