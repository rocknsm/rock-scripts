@load ../__load__.bro

module FileExtraction;

const script_types: set[string] = { 
                                "text/x-shellscript",
								"text/x-perl",
					   			"text/x-ruby",
					   			"text/x-python",
					   			"text/x-awk",
                                "text/x-tcl",
                                "text/x-lua",
                                #"application/javascript", # Let's skip this one, but listing for completeness
                                "text/x-php"
								};

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( meta$mime_type in script_types )
		break;
	}
