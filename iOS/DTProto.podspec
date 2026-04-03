

Pod::Spec.new do |s|

  PROTOVERSION = "3.0.0"
  
  s.name             = "DTProto"
  s.version          = "#{PROTOVERSION}"
  s.summary          = "message protocol"

  s.description      = <<-DESC
message protocol.
  DESC

  s.homepage         = "https://github.com/TempTalkOrg/dtproto"
  s.license          = 'AGPL-3.0'
  s.author           = { "TempTalkOrg" => "https://github.com/TempTalkOrg" }
  s.source           = { :git => "https://github.com/TempTalkOrg/dtproto.git", :tag => s.version.to_s }

  s.platform     = :ios, '10.0'
  #s.ios.deployment_target = '9.0'
  #s.osx.deployment_target = '10.9'
  s.requires_arc = true
  s.source_files = 'DTProto/*.swift'

#  s.ios.vendored_library = 'DTProto/*.a'
  
  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/DTProto/dtprotoFFI',
    'DTPROTOTARGETLIB' => "libuniffi_dtproto_#{PROTOVERSION}",
    'DTPROTOLIBROOT' => '${PODS_TARGET_SRCROOT}/DTProto/libuniffi_dtproto',
    'DTPROTO_FFI_LIB_TO_LINK' => '${DTPROTOLIBROOT}/${DTPROTOTARGETLIB}/libuniffi_dtproto.a',
    'OTHER_LDFLAGS' => '$(DTPROTO_FFI_LIB_TO_LINK)'
  }
  
  s.script_phases = [
      { name: 'Download and cache libuniffi_dtproto',
        execution_position: :before_compile,
        script: %q(
           set -euo pipefail
           DTPROTOTARGETLIBZIP="${DTPROTOTARGETLIB}.zip"
           if [ -e "${DTPROTOLIBROOT}/${DTPROTOTARGETLIB}/libuniffi_dtproto.a" ]; then
             # exists
             exit 0
           fi
           cd "${DTPROTOLIBROOT}"

           curl -OL "https://github.com/TempTalkOrg/dtproto/releases/download/v#{PROTOVERSION}/${DTPROTOTARGETLIBZIP}"

           if [ -e "${DTPROTOTARGETLIBZIP}" ]; then
             unzip "${DTPROTOTARGETLIBZIP}"  -x '__MACOSX/*'
           fi
           if [ -e "${DTPROTOTARGETLIBZIP}" ]; then
             rm "${DTPROTOTARGETLIBZIP}"
           fi
        )
      }
  ]
  
  
end
