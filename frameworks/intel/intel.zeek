@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

# See https://www.bro.org/sphinx-git/frameworks/intel.html
# for info on how to customize

redef Intel::read_files += {
  fmt("%s/intel-1.dat", @DIR),
};
