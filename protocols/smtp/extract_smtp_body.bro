event protocol_confirmation (c: connection, atype: Analyzer::Tag, aid: count)
{
  if ( atype == Analyzer::ANALYZER_SMTP )
  {
    local body_file = generate_extraction_filename(Conn::extraction_prefix, c, "client.txt");
    local body_f = open(body_file);
    set_contents_file(c$id, CONTENTS_ORIG, body_f);
  }
}
