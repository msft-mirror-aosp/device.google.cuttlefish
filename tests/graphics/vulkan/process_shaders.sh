if ! command -v generate_shader_embed_header 2>&1 >/dev/null; then
    m generate_shader_embed_header
fi

for file in **/*.{frag,vert}; do
    [ -f "${file}" ] || break

    SHADER_GLSL="${file}"
    echo "Found ${SHADER_GLSL}"

    SHADER_SPV="${file}.spv"
    SHADER_EMBED="${file}.inl"
    SHADER_BASENAME="$(basename ${file})"
    SHADER_EMBED_VARNAME=$(sed -r 's/\./_/g' <<< $SHADER_BASENAME)
    SHADER_EMBED_VARNAME=$(sed -r 's/(^|_)([a-z])/\U\2/g' <<< $SHADER_EMBED_VARNAME)
    SHADER_EMBED_VARNAME="k${SHADER_EMBED_VARNAME}"

    glslc \
        "${SHADER_GLSL}" \
        -o "${SHADER_SPV}"

    generate_shader_embed_header \
        "${SHADER_GLSL}" \
        "${SHADER_SPV}" \
        "${SHADER_EMBED_VARNAME}" \
        "${SHADER_EMBED}"

    echo "Generated ${SHADER_EMBED}"
done
