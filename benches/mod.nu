const FQ_MODULUS_BIT_SIZE = 128
const FQ_MODULUS_BYTE_SIZE = $FQ_MODULUS_BIT_SIZE // 8

def run [bench: string]: [ nothing -> path ] {
    let out = mktemp --tmpdir $"($bench | str downcase)-XXXXXXX.ndjson"
    print $"dumping (ansi cyan)($bench)(ansi reset) benchmark results to (ansi purple)($out)(ansi reset)"
    cargo criterion --output-format verbose --message-format json --bench $bench out> $out
    print $"(ansi cyan)($bench)(ansi reset) benchmark results dumped to (ansi purple)($out)(ansi reset)"

    $out
}

export def "run fri" []: [ nothing -> path ] {
    run "fri"
}

export def "run frida" []: [ nothing -> path ] {
    run "frida"
}

export def "parse fri" []: [
    table<reason: string, id: string, mean: record<estimate: float>>
        -> table<stage: string, t: duration>
] {
    where reason == "benchmark-complete"
        | select id mean.estimate
        | rename --column { "mean.estimate": 't' }
        | update id {
            parse "{stage} {o}"
                | update o { str replace --all '=' ':' | $"{($in)}" | from nuon }
                | flatten
        }
        | flatten --all
        | update t { into int | into duration }
}

export def "parse frida" []: [
    table<reason: string, id: string, mean: record<estimate: float>>
        -> table<stage: string, t: duration, k: int, m: int, nbytes: filesize>
] {
    where reason == "benchmark-complete"
        | select id mean.estimate
        | rename --column { "mean.estimate": 't' }
        | update id {
            parse "{stage} {o}"
                | update o {
                    let res = $in | parse "{metadata}/{v}" | into record;
                    $res.metadata
                        | str replace '#' $res.v
                        | str replace --all '#' '"#"'
                        | str replace --all '=' ':'
                        | $"{($in)}"
                        | from nuon
                }
                | flatten
        }
        | flatten --all
        | update t { into int | into duration }
        | update m { |it|
            if $it.m == '#' { $it.nbytes / $it.k / $FQ_MODULUS_BYTE_SIZE } else { $it.m }
        }
        | default null nbytes
        | update nbytes { |it|
            $it.nbytes? | default ($it.k * $it.m * $FQ_MODULUS_BYTE_SIZE) | into filesize
        }
}
