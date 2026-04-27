#!/usr/bin/env bash
#
# dtproto Android Maven 私有仓库发布脚本
#
# 用法: bash Android/publish-maven.sh <VERSION> <ANDROID_REPO_PATH>
# 示例: bash Android/publish-maven.sh 3.1.0 ../AndroidRepo
#
set -e

VERSION="${1:?用法: $0 <VERSION> <ANDROID_REPO_PATH>}"
ANDROID_REPO="${2:?用法: $0 <VERSION> <ANDROID_REPO_PATH>}"

PROJECTPATH="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT_ID="dtproto"
GROUP_PATH="org/difft/android/libraries"
MAVEN_LOCAL="${HOME}/.m2/repository/${GROUP_PATH}/${ARTIFACT_ID}/${VERSION}"
REPO_DEST="$(cd "${ANDROID_REPO}" && pwd)/${GROUP_PATH}/${ARTIFACT_ID}"
METADATA_XML="${REPO_DEST}/maven-metadata.xml"

# 前置检查
if [ -z "${ANDROID_NDK_HOME}" ]; then
    echo "错误: ANDROID_NDK_HOME 未设置"
    exit 1
fi

echo "=========================================="
echo "  dtproto ${VERSION} 发布流程"
echo "=========================================="

# Step 0: 清理 Rust 编译缓存
echo ""
echo "[0/4] 清理 Rust 编译缓存..."
cd "${PROJECTPATH}"
cargo clean
echo "  ✓ cargo clean 完成"

# Step 1: 编译 Rust → .so + Kotlin bindings
echo ""
echo "[1/4] 编译 Rust (交叉编译 Android .so + 生成 Kotlin bindings)..."
bash "${PROJECTPATH}/Android/android-dtproto-jniLibs.sh"

# 验证 .so 文件已更新
JNILIBS="${PROJECTPATH}/Android/dtproto/src/main/jniLibs"
for arch in arm64-v8a armeabi-v7a x86_64; do
    SO_FILE="${JNILIBS}/${arch}/libuniffi_dtproto.so"
    if [ ! -f "${SO_FILE}" ]; then
        echo "错误: ${SO_FILE} 不存在"
        exit 1
    fi
    echo "  ✓ ${arch}: $(wc -c < "${SO_FILE}") bytes"
done

# Step 2: 清理缓存 + 发布到 Maven local
echo ""
echo "[2/4] 发布到 Maven local..."
rm -rf "${MAVEN_LOCAL}"
cd "${PROJECTPATH}/Android"
./gradlew clean :dtproto:publishReleasePublicationToMavenLocal -PVERSION_NAME="${VERSION}" --quiet

# 验证产物
AAR_FILE="${MAVEN_LOCAL}/${ARTIFACT_ID}-${VERSION}.aar"
if [ ! -f "${AAR_FILE}" ]; then
    echo "错误: AAR 文件未生成: ${AAR_FILE}"
    exit 1
fi
echo "  ✓ AAR: $(wc -c < "${AAR_FILE}") bytes"

# Step 3: 复制到 AndroidRepo + 生成 checksum (仅 md5 + sha1)
echo ""
echo "[3/4] 复制产物到 AndroidRepo..."
DEST="${REPO_DEST}/${VERSION}"
mkdir -p "${DEST}"

for f in "${MAVEN_LOCAL}"/*; do
    fname=$(basename "$f")
    cp "$f" "${DEST}/${fname}"
    md5 -q "$f" > "${DEST}/${fname}.md5"
    shasum -a 1 "$f" | awk '{print $1}' > "${DEST}/${fname}.sha1"
done

echo "  ✓ $(ls "${DEST}" | wc -l | tr -d ' ') 个文件"

# Step 4: 更新 maven-metadata.xml
echo ""
echo "[4/4] 更新 maven-metadata.xml..."
TIMESTAMP=$(date -u +%Y%m%d%H%M%S)

if [ -f "${METADATA_XML}" ]; then
    # 检查版本是否已存在
    if grep -q "<version>${VERSION}</version>" "${METADATA_XML}"; then
        # 版本已存在，只更新 release 和 lastUpdated
        sed -i '' "s|<release>[^<]*</release>|<release>${VERSION}</release>|" "${METADATA_XML}"
        sed -i '' "s|<lastUpdated>[^<]*</lastUpdated>|<lastUpdated>${TIMESTAMP}</lastUpdated>|" "${METADATA_XML}"
    else
        # 新增版本
        sed -i '' "s|<release>[^<]*</release>|<release>${VERSION}</release>|" "${METADATA_XML}"
        sed -i '' "s|</versions>|      <version>${VERSION}</version>\n    </versions>|" "${METADATA_XML}"
        sed -i '' "s|<lastUpdated>[^<]*</lastUpdated>|<lastUpdated>${TIMESTAMP}</lastUpdated>|" "${METADATA_XML}"
    fi
else
    cat > "${METADATA_XML}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.difft.android.libraries</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <versioning>
    <release>${VERSION}</release>
    <versions>
      <version>${VERSION}</version>
    </versions>
    <lastUpdated>${TIMESTAMP}</lastUpdated>
  </versioning>
</metadata>
EOF
fi

# 生成 metadata checksum
md5 -q "${METADATA_XML}" > "${METADATA_XML}.md5"
shasum -a 1 "${METADATA_XML}" | awk '{print $1}' > "${METADATA_XML}.sha1"

echo "  ✓ release=${VERSION}, lastUpdated=${TIMESTAMP}"

echo ""
echo "=========================================="
echo "  发布完成！"
echo "=========================================="
echo ""
echo "下一步:"
echo "  cd ${ANDROID_REPO}"
echo "  git checkout -b dtproto-${VERSION}"
echo "  git add ${GROUP_PATH}/${ARTIFACT_ID}/"
echo "  git commit -m 'release dtproto ${VERSION}'"
echo "  git push -u origin dtproto-${VERSION}"
echo "  # 然后创建 PR 合并到 main"
