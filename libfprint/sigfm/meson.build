
sigfm_sources = ['sigfm.cpp']

# SIGFM needs OpenCV. Distro pkg-config files are named opencv4 (OpenCV 4.x)
# or opencv5 (OpenCV 5.x); accept either. Include as system headers so
# third-party warnings do not pollute the build.
opencv = dependency('opencv4', include_type: 'system', required: false)
if not opencv.found()
  opencv = dependency('opencv5', include_type: 'system')
endif

libsigfm = static_library('sigfm', sigfm_sources, dependencies: [opencv])
