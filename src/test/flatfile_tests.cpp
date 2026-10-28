// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <common/args.h>
#include <flatfile.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(flatfile_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(flatfile_filename)
{
    const auto data_dir = m_args.GetDataDirBase();

    FlatFilePos pos(456, 789);

    FlatFileSeq seq1(data_dir, "a", 16 * 1024);
    BOOST_CHECK_EQUAL(seq1.FileName(pos), data_dir / "a00456.dat");

    FlatFileSeq seq2(data_dir / "a", "b", 16 * 1024);
    BOOST_CHECK_EQUAL(seq2.FileName(pos), data_dir / "a" / "b00456.dat");

    // Check default constructor IsNull
    assert(FlatFilePos{}.IsNull());
}

BOOST_AUTO_TEST_CASE(flatfile_open)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 16 * 1024);

    std::string line1("A purely peer-to-peer version of electronic cash would allow online "
                      "payments to be sent directly from one party to another without going "
                      "through a financial institution.");
    std::string line2("Digital signatures provide part of the solution, but the main benefits are "
                      "lost if a trusted third party is still required to prevent double-spending.");

    size_t pos1 = 0;
    size_t pos2 = pos1 + GetSerializeSize(line1);

    // Write first line to file.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos1))};
        file << LIMITED_STRING(line1, 256);
    }

    // Attempt to append to file opened in read-only mode.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos2), true)};
        BOOST_CHECK_THROW(file << LIMITED_STRING(line2, 256), std::ios_base::failure);
    }

    // Append second line to file.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos2))};
        file << LIMITED_STRING(line2, 256);
    }

    // Read text from file in read-only mode.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(0, pos1), true)};

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line1);

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line2);
    }

    // Read text from file with position offset.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(0, pos2))};

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line2);
    }

    // Ensure another file in the sequence has no data.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(1, pos2))};
        BOOST_CHECK_THROW(file >> LIMITED_STRING(text, 256), std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(flatfile_allocate)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 100);

    bool out_of_space;

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 0), 1, out_of_space), 100U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 0))), 100U);
    BOOST_CHECK(!out_of_space);

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 99), 1, out_of_space), 0U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 99))), 100U);
    BOOST_CHECK(!out_of_space);

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 99), 2, out_of_space), 101U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 99))), 200U);
    BOOST_CHECK(!out_of_space);
}

BOOST_AUTO_TEST_CASE(flatfile_flush)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 100);

    bool out_of_space;
    seq.Allocate(FlatFilePos(0, 0), 1, out_of_space);

    // Flush without finalize should not truncate file.
    seq.Flush(FlatFilePos(0, 1));
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 1))), 100U);

    // Flush with finalize should truncate file.
    seq.Flush(FlatFilePos(0, 1), true);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 1))), 1U);
}

BOOST_AUTO_TEST_CASE(flatfile_large_offsets)
{
    FlatFileSeq seq{m_args.GetDataDirBase(), "large", 4096};
    const FlatFilePos low{0, 17};
    {
        AutoFile file{seq.Open(low)};
        file << uint8_t{0x11};
    }
    for (const uint64_t offset : {(uint64_t{1} << 31) + 17, (uint64_t{1} << 32) + 17}) {
        const FlatFilePos pos{0, offset};
        DataStream stream;
        stream << pos;
        FlatFilePos decoded;
        stream >> decoded;
        BOOST_CHECK_EQUAL(decoded.nPos, offset);
        BOOST_CHECK(decoded == pos);

        CBlockFileInfo info;
        info.nSize = offset;
        info.nUndoSize = offset + 1;
        stream << info;
        CBlockFileInfo restored;
        stream >> restored;
        BOOST_CHECK_EQUAL(restored.nSize, offset);
        BOOST_CHECK_EQUAL(restored.nUndoSize, offset + 1);

        // Sparse writes exercise both signed-32-bit seek and unsigned-32-bit
        // position boundaries without allocating gigabytes of test data.
        {
            AutoFile file{seq.Open(pos)};
            BOOST_CHECK_EQUAL(file.tell(), offset);
            file << uint8_t{0x42};
            BOOST_REQUIRE(file.Commit());
            BOOST_REQUIRE(file.Truncate(offset + 1));
            file.seek(-1, SEEK_END);
            BOOST_CHECK_EQUAL(file.tell(), offset);
            uint8_t value;
            file >> value;
            BOOST_CHECK_EQUAL(value, 0x42);
        }
        BOOST_REQUIRE(seq.Flush(FlatFilePos{0, offset + 1}, true));
        BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(pos)), offset + 1);
        AutoFile file{seq.Open(low, true)};
        uint8_t value;
        file >> value;
        BOOST_CHECK_EQUAL(value, 0x11);
    }
}

BOOST_AUTO_TEST_SUITE_END()
