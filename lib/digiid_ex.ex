defmodule DigiID do

  alias Digibyte.Core

  require Logger

  defstruct nonce: nil,
    callback: nil,
    secure: true

  @scheme "digiid"
  @param_nonce "x"
  @param_unsecure "u"

  @doc """
  generates a uri for a DigiID
  """
  def generate_uri(digiid) do
    params = case digiid.secure do
      false -> %{@param_nonce => digiid.nonce, @param_unsecure => "1"}
      _ -> %{@param_nonce => digiid.nonce}
    end
    digiid.callback
    |> URI.parse()
    |> Map.put(:scheme, @scheme)
    |> Map.put(:query, URI.encode_query(params))
    |> URI.to_string()
  end

  @doc """
  generates the uri for a DigiID qrcode
  """
  def qrcode(digiid) do
    # google chart query string params
    qs = %{
      "cht" => "qr",
      "chs" => "300x300",
      "chl" => generate_uri(digiid)
    } |> URI.encode_query()
    "http://chart.apis.google.com/chart?#{qs}"
  end

  @doc """
  Returns true if the submitted URI is valid and corresponds to the correct callback url.
  """
  def uri_valid?(digiid, uri) do
    generate_uri(digiid) == uri
  end

  @doc """
  If returns true, then you can authenticate the user's session with address
  (public Digibyte address used to sign the challenge).
  """
  def signature_valid?(uri, address, signature) do
    # recover public key from message (uri)
    pub_key = Core.ecdsa_recover(uri, signature)
    Logger.debug "Recovered pubkey from signature #{inspect pub_key}"
    # make sure recovered public key matches received address
    # convert pubkey to address use livenet magic byte 0x1e
    recovered_address = Core.pubkey_to_address(pub_key, 0x1e)
    Logger.debug "recovered address from pubkey=#{recovered_address}"
    cond do
      recovered_address != address -> false
      true ->
        # verify signature
        Core.ecdsa_verify(uri, signature, address)
    end
  end
end
