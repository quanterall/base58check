defmodule Base58Check do

  @moduledoc """
  This module is used for encoding and decoding in a Base58 format.
  It also protects against errors in address transcription and entry.
  """

  b58_alphabet = Enum.with_index('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')

  for {encoding, value} <- b58_alphabet do
    defp do_encode58(unquote(value)), do: unquote(encoding)
    defp do_decode58(unquote(encoding)), do: unquote(value)
  end

  @doc """
  Converts the data into a Base58 format.
  Tested and works with: integers, <<4,15,128>>, strings and even cyrillic strings.

  The leading character '1', which has a value of zero in base58,
  is reserved for representing an entire leading zero byte,
  as when it is in a leading position, has no value as a base-58 symbol.

  ## Examples
    iex> encode58("encode this")
         "S9qetuAJP32Bbu4"
  """
  @spec encode58(Integer.t()) :: String.t()
  def encode58(data) do
    encoded_zeroes = convert_leading_zeroes(data, [])
    integer = if is_binary(data), do: :binary.decode_unsigned(data), else: data
    encode58(integer, [], encoded_zeroes)
  end
  defp encode58(0, acc, encoded_zeroes), do: to_string([encoded_zeroes|acc])
  defp encode58(integer, acc, encoded_zeroes) do
    encode58(div(integer, 58), [do_encode58(rem(integer, 58)) | acc], encoded_zeroes)
  end
  defp convert_leading_zeroes(<<0>> <> data, encoded_zeroes) do
    encoded_zeroes = ['1'|encoded_zeroes]
    convert_leading_zeroes(data, encoded_zeroes)
  end
  defp convert_leading_zeroes(_data, encoded_zeroes), do: encoded_zeroes

  @doc """
  Converts the Base58 format data into an integer.
  Tested and works only with strings.

  ## Examples
    iex> decode58("S9qetuAJP32Bbu4")
         122622802348508130811865459
  """
  @spec decode58(String.t()) :: Integer.t()
  def decode58(code) when is_binary(code) do
    decode58(to_char_list(code), 0)
  end
  def decode58(code), do: raise(ArgumentError, "expects base58-encoded binary")
  defp decode58([], acc), do: acc
  defp decode58([c|code], acc) do
    decode58(code, (acc * 58) + do_decode58(c))
  end

  @doc """
    Combines a prefix and checksum to the data, altered data is then encoded using the Base58 alphabet.

    The prefix (called a "version byte") is added (concatenated) to the front of the data,
    it serves to easily identify the type of data that is encoded.

    The checksum, which serves as error-checking code, is generated from another function.
    It is computed from a "double-SHA" (hash of a hash) of the encoded data,
    as in we apply the SHA256 hash-algorithm twice on the previous result (prefix and data),
    with the checksum being the first four bytes of that.
    The checksum gets added(concatenated) to the end of the data.

    If the prefix or data are integers, they are ignored.

  ## Examples
    iex> encode58check("1","encode this")
         "76nEwkNLaCwXLSDfagT6o5"

    iex> encode58check(1,"asd")
         <<1>>
         "EPs5zLP2T9"
  """
  @spec encode58check(String.t(), String.t()) :: String.t()
  def encode58check(prefix, data) when is_binary(prefix) and is_binary(data) do
    data = case Base.decode16(String.upcase(data)) do
        {:ok, bin}  ->  bin
        :error      ->  data
      end
    versioned_data = prefix <> data
    checksum = generate_checksum(versioned_data)
    encode58(versioned_data <> checksum)
  end
  def encode58check(prefix, data) do
    prefix = if is_integer(prefix), do: :binary.encode_unsigned(prefix), else: prefix
    IO.inspect prefix
    data = if is_integer(data), do: :binary.encode_unsigned(data), else: data
    encode58check(prefix, data)
  end

  @doc """
  Checks for and prevents a mistyped address from being accepted by the wallet software as a valid destination,
  an error that would otherwise result in loss of funds.

  Since the checksum is derived from the hash of the encoded data
  it can therefore be used to detect and prevent transcription and typing errors.
  When presented with Base58Check code, the decoding software will calculate the checksum of the data
  and compare it to the checksum included in the code.
  If the two do not match, an error has been introduced and the Base58Check data is invalid.

  Tested and works only with strings.

  ## Examples
    iex> decode58check("76nEwkNLaCwXLSDfagT6o5")
         {"1", "encode this"}

    iex> decode58check("EPs5zLP2T9")
         {<<1>>, "asd"}
  """
  @spec decode58check(String.t()) :: Tuple.t()
  def decode58check(code) do
    decoded_bin = decode58(code) |> :binary.encode_unsigned()
    payload_size = byte_size(decoded_bin) - 5

    <<prefix::binary-size(4), payload::binary-size(payload_size), checksum::binary-size(4)>> = decoded_bin
    if generate_checksum(prefix <> payload) == checksum do
      {prefix, payload}
    else
      raise ArgumentError, "checksum doesn't match"
    end
  end

  defp generate_checksum(versioned_data) do
    <<checksum::binary-size(4), _rest::binary-size(28)>> = :crypto.hash(:sha256, :crypto.hash(:sha256, versioned_data))
    checksum
  end

end
