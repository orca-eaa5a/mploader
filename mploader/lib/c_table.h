#ifndef CONSOLE_TABLE_H
#define CONSOLE_TABLE_H

#include <iostream>
#include <vector>
#include <iterator>
#include <iomanip>
#include <numeric>
#include <algorithm>
#include <memory>
#include <sstream>
#include <forward_list>

enum class Align { Left, Right, Center };
typedef std::forward_list<std::string> Row;

class ConsoleTable
{
public:
	ConsoleTable() = delete;
	~ConsoleTable() = default;
	ConsoleTable(unsigned int numberOfColumns);

public:
	void WriteTable(Align align = Align::Left, std::ostream* stream = &std::cout) const;
	void AddNewRow(const std::forward_list<std::string>& list);

private:
	void GenerateStream(std::stringstream&, Align align, int i, const std::vector<int>& columnsWidth) const;
	std::string AlignRowToLeftOrRight(Align align, int index, const std::vector<int>& columnsWidth) const;
	std::string AlignRowToCenter(int index, const std::vector<int>& columnsWidth) const;
	void WriteBorderToStream(int width, std::stringstream* stream) const;
	std::vector<int> GetColumnsMaxWidth() const;

private:
	unsigned int _numberOfColumns;
	std::vector<std::vector<std::string>> _rows;
};
#endif